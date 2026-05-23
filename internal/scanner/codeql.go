package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vulnscanner/internal/logging"
)

var extToCodeQLLang = map[string]string{
	".go": "go",
}

var codeqlSuites = map[string]string{
	"go": "codeql/go-queries:codeql-suites/go-code-scanning.qls",
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func IsCodeQLAvailable() bool {
	_, err := exec.LookPath("codeql")
	return err == nil
}

func ScanWithCodeQL(root string, files []string, onStatus func(string)) ([]Finding, error) {
	langs := codeqlLanguagesFromFiles(files)
	if len(langs) == 0 {
		return nil, fmt.Errorf("no CodeQL-supported source files detected")
	}

	status := func(msg string) {
		logging.L().Info("codeql progress", "message", msg)
		if onStatus != nil {
			onStatus(msg)
		}
	}

	pruneGeneratedFiles(root)
	writeCodeQLIgnore(root)

	type result struct {
		lang     string
		findings []Finding
		err      error
	}
	ch := make(chan result, len(langs))
	for _, l := range langs {
		go func(lang string) {
			status(fmt.Sprintf("CodeQL: создание базы (%s)…", lang))
			found, err := runCodeQLForLang(root, lang, func(stage string) {
				status(fmt.Sprintf("CodeQL [%s]: %s", lang, stage))
			})
			ch <- result{lang, found, err}
		}(l)
	}

	var all []Finding
	successCount := 0
	var failedMsgs []string
	for range langs {
		r := <-ch
		if r.err != nil {
			logging.L().Warn("codeql language failed", "lang", r.lang, "err", r.err)
			failedMsgs = append(failedMsgs, r.lang+": "+r.err.Error())
		} else {
			successCount++
			all = append(all, r.findings...)
			status(fmt.Sprintf("CodeQL [%s]: найдено %d находок", r.lang, len(r.findings)))
		}
	}

	if successCount == 0 {
		return nil, fmt.Errorf("CodeQL failed for all detected languages (%s)",
			strings.Join(failedMsgs, "; "))
	}
	return all, nil
}

func pruneGeneratedFiles(root string) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, "_gen.go") ||
			strings.HasSuffix(name, "_generated.go") ||
			strings.HasSuffix(name, ".pb.go") ||
			strings.HasSuffix(name, ".pb.gw.go") ||
			strings.HasSuffix(name, "_mock.go") {
			_ = os.Remove(path)
		}
		return nil
	})
}

func writeCodeQLIgnore(root string) {
	target := filepath.Join(root, ".codeqlignore")
	if _, err := os.Stat(target); err == nil {
		return
	}
	const content = `vendor/
third_party/
node_modules/
generated/
**/generated/
**/*_gen.go
**/*_generated.go
**/*.pb.go
**/*_pb.go
**/*.pb.gw.go
testdata/
**/testdata/
.git/
`
	_ = os.WriteFile(target, []byte(content), 0644)
}

func codeqlLanguagesFromFiles(files []string) []string {
	seen := map[string]bool{}
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if lang, ok := extToCodeQLLang[ext]; ok {
			seen[lang] = true
		}
	}
	var result []string
	for _, lang := range []string{"go", "python", "cpp", "csharp"} {
		if seen[lang] {
			result = append(result, lang)
		}
	}
	return result
}

func runCodeQLForLang(root, language string, onStage func(string)) ([]Finding, error) {
	stage := func(msg string) {
		logging.L().Info("codeql stage", "lang", language, "stage", msg)
		if onStage != nil {
			onStage(msg)
		}
	}
	dbDir, err := os.MkdirTemp("", "codeql-db-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dbDir)

	createArgs := []string{
		"database", "create", dbDir,
		"--language=" + language,
		"--source-root=" + root,
		"--overwrite",
		"--threads=0",
		"--ram=2048",
	}

	stage("извлечение исходного кода…")
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel1()
	out, err := runCodeQLStep(ctx1, "извлечение исходного кода…", stage, createArgs...)
	if err != nil {
		return nil, fmt.Errorf("database create: %w\n%s", err, bytes.TrimSpace(out))
	}
	logging.L().Info("codeql database created", "lang", language)

	suite, ok := codeqlSuites[language]
	if !ok {
		return nil, fmt.Errorf("no query suite for language %q", language)
	}
	sarifPath := filepath.Join(dbDir, "results.sarif")

	stage("запуск security-запросов…")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel2()
	out, err = runCodeQLStep(ctx2, "запуск security-запросов…", stage,
		"database", "analyze", dbDir,
		"--format=sarif-latest",
		"--output="+sarifPath,
		"--threads=0",
		"--ram=2048",
		suite,
	)
	if err != nil {
		return nil, fmt.Errorf("database analyze: %w\n%s", err, bytes.TrimSpace(out))
	}
	logging.L().Info("codeql database analyzed", "lang", language)
	stage("анализ завершён, разбор результатов…")

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("reading results: %w", err)
	}
	return parseSARIFFindings(data, root)
}

func runCodeQLStep(ctx context.Context, stageName string, stage func(string), args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "codeql", args...)
	var (
		buf  bytes.Buffer
		done = make(chan error, 1)
	)
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	started := time.Now()
	doneMsg := "выполняется…"
	go func() {
		done <- cmd.Run()
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			return buf.Bytes(), err
		case <-ticker.C:
			elapsed := int(time.Since(started).Seconds())
			stage(fmt.Sprintf("%s %s (%ds)", stageName, doneMsg, elapsed))
		case <-ctx.Done():
			// Keep waiting for cmd.Run() to return with context cancellation error.
		}
	}
}

type codeqlSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					FullDescription struct {
						Text string `json:"text"`
					} `json:"fullDescription"`
					Help struct {
						Text string `json:"text"`
					} `json:"help"`
					Properties struct {
						SecuritySeverity string `json:"security-severity"`
						ProblemSeverity  string `json:"problem.severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIFFindings(data []byte, root string) ([]Finding, error) {
	var sarif codeqlSARIF
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	var findings []Finding
	for _, run := range sarif.Runs {
		type ruleInfo struct {
			title    string
			why      string
			fix      string
			severity Severity
		}
		ruleMap := make(map[string]ruleInfo, len(run.Tool.Driver.Rules))
		for _, r := range run.Tool.Driver.Rules {
			ruleMap[r.ID] = ruleInfo{
				title:    r.ShortDescription.Text,
				why:      truncateStr(r.FullDescription.Text, 500),
				fix:      sarifExtractRemediation(r.Help.Text),
				severity: sarifSeverity(r.Properties.SecuritySeverity, r.Properties.ProblemSeverity, ""),
			}
		}

		for _, result := range run.Results {
			if len(result.Locations) == 0 {
				continue
			}
			ploc := result.Locations[0].PhysicalLocation
			uri := ploc.ArtifactLocation.URI

			absFile := uri
			if !filepath.IsAbs(uri) {
				absFile = filepath.Join(root, filepath.FromSlash(uri))
			}

			line := ploc.Region.StartLine
			if line <= 0 {
				line = 1
			}
			col := ploc.Region.StartColumn
			if col <= 0 {
				col = 1
			}

			info, hasRule := ruleMap[result.RuleID]
			title := result.RuleID
			why, fix := "", ""
			sev := sarifSeverity("", "", result.Level)
			if hasRule {
				if info.title != "" {
					title = info.title
				}
				why = info.why
				fix = info.fix
				sev = info.severity
			}

			ruleID := "CODEQL-" + strings.ToUpper(
				strings.NewReplacer("/", "-", ".", "-", " ", "-").Replace(result.RuleID))

			findings = append(findings, Finding{
				RuleID:       ruleID,
				Title:        title,
				Severity:     sev,
				File:         absFile,
				Line:         line,
				Column:       col,
				Evidence:     truncateStr(result.Message.Text, 120),
				WhyItMatters: why,
				Remediation:  fix,
			})
		}
	}
	return findings, nil
}

func sarifSeverity(secScore, problemSev, level string) Severity {
	if secScore != "" {
		if v, err := strconv.ParseFloat(secScore, 64); err == nil {
			switch {
			case v >= 9.0:
				return SeverityCritical
			case v >= 7.0:
				return SeverityHigh
			case v >= 4.0:
				return SeverityMedium
			default:
				return SeverityLow
			}
		}
	}
	switch strings.ToLower(problemSev) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "recommendation":
		return SeverityLow
	}
	switch strings.ToLower(level) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func sarifExtractRemediation(help string) string {
	if help == "" {
		return ""
	}
	const marker = "## Recommendation"
	if idx := strings.Index(help, marker); idx >= 0 {
		rest := strings.TrimSpace(help[idx+len(marker):])
		if next := strings.Index(rest, "\n## "); next >= 0 {
			rest = rest[:next]
		}
		return truncateStr(strings.TrimSpace(rest), 400)
	}
	return truncateStr(strings.TrimSpace(help), 400)
}
