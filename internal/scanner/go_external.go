package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vulnscanner/internal/logging"
)

const externalScannerTimeout = 5 * time.Minute

func IsGosecAvailable() bool {
	_, err := exec.LookPath("gosec")
	return err == nil
}

func IsGovulncheckAvailable() bool {
	_, err := exec.LookPath("govulncheck")
	return err == nil
}

func ScanWithGosec(root string, onStatus func(string)) ([]Finding, error) {
	statusScanner(onStatus, "gosec: запуск Go security rules…")
	ctx, cancel := context.WithTimeout(context.Background(), externalScannerTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-no-fail", "./...")
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("gosec timeout after %s: %w", externalScannerTimeout, ctx.Err())
	}
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("gosec: %w\n%s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	findings, err := parseGosecFindings(stdout.Bytes(), root)
	if err != nil {
		return nil, err
	}
	statusScanner(onStatus, fmt.Sprintf("gosec: найдено %d находок", len(findings)))
	return findings, nil
}

func ScanWithGovulncheck(root string, onStatus func(string)) ([]Finding, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, fmt.Errorf("govulncheck requires go.mod in scan root")
	}
	statusScanner(onStatus, "govulncheck: проверка Go dependency vulnerabilities…")
	ctx, cancel := context.WithTimeout(context.Background(), externalScannerTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("govulncheck timeout after %s: %w", externalScannerTimeout, ctx.Err())
	}
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("govulncheck: %w\n%s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	findings, parseErr := parseGovulncheckFindings(stdout.Bytes(), root)
	if parseErr != nil {
		return nil, parseErr
	}
	statusScanner(onStatus, fmt.Sprintf("govulncheck: найдено %d уязвимостей", len(findings)))
	return findings, nil
}

func statusScanner(onStatus func(string), msg string) {
	logging.L().Info("external scanner progress", "message", msg)
	if onStatus != nil {
		onStatus(msg)
	}
}

type gosecReport struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	CWE        struct {
		ID string `json:"id"`
	} `json:"cwe"`
	RuleID  string `json:"rule_id"`
	Details string `json:"details"`
	File    string `json:"file"`
	Code    string `json:"code"`
	Line    string `json:"line"`
	Column  string `json:"column"`
}

func parseGosecFindings(data []byte, root string) ([]Finding, error) {
	var report gosecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse gosec json: %w", err)
	}
	findings := make([]Finding, 0, len(report.Issues))
	for _, issue := range report.Issues {
		ruleID := normalizeExternalRuleID("GOSEC", issue.RuleID)
		line := parsePositiveInt(issue.Line, 1)
		col := parsePositiveInt(issue.Column, 1)
		file := absoluteFindingPath(root, issue.File)
		why := "gosec rule " + strings.TrimPrefix(ruleID, "GOSEC-") + " reported a Go security issue."
		if issue.CWE.ID != "" {
			why += " CWE-" + issue.CWE.ID + "."
		}
		findings = append(findings, Finding{
			RuleID:       ruleID,
			Title:        firstNonEmpty(issue.Details, issue.RuleID),
			Severity:     externalSeverity(issue.Severity),
			File:         file,
			Line:         line,
			Column:       col,
			Evidence:     truncateStr(strings.TrimSpace(issue.Code), 160),
			WhyItMatters: why,
			Remediation:  "Review the gosec finding and replace the unsafe Go API or pattern with a safer implementation.",
		})
	}
	return findings, nil
}

type govulnFinding struct {
	OSV          string        `json:"osv"`
	FixedVersion string        `json:"fixed_version"`
	Trace        []govulnFrame `json:"trace"`
}

type govulnFrame struct {
	Module   string         `json:"module"`
	Package  string         `json:"package"`
	Function string         `json:"function"`
	Position govulnPosition `json:"position"`
}

type govulnPosition struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type govulnOSV struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
	Aliases []string `json:"aliases"`
}

func parseGovulncheckFindings(data []byte, root string) ([]Finding, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	osvByID := map[string]govulnOSV{}
	var rawFindings []govulnFinding

	for {
		var msg struct {
			Finding *govulnFinding `json:"finding"`
			OSV     *govulnOSV     `json:"osv"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse govulncheck json: %w", err)
		}
		if msg.OSV != nil && msg.OSV.ID != "" {
			osvByID[msg.OSV.ID] = *msg.OSV
		}
		if msg.Finding != nil && msg.Finding.OSV != "" {
			rawFindings = append(rawFindings, *msg.Finding)
		}
	}

	findings := make([]Finding, 0, len(rawFindings))
	for _, vuln := range rawFindings {
		meta := osvByID[vuln.OSV]
		frame := bestGovulnFrame(vuln.Trace)
		line := frame.Position.Line
		if line <= 0 {
			line = 1
		}
		col := frame.Position.Column
		if col <= 0 {
			col = 1
		}
		file := absoluteFindingPath(root, frame.Position.Filename)
		evidence := govulnEvidence(vuln, meta, frame)
		remediation := "Upgrade the affected Go module to a non-vulnerable version."
		if vuln.FixedVersion != "" {
			remediation = "Upgrade the affected Go module to " + vuln.FixedVersion + " or later."
		}
		findings = append(findings, Finding{
			RuleID:       normalizeExternalRuleID("GOVULN", vuln.OSV),
			Title:        firstNonEmpty(meta.Summary, vuln.OSV),
			Severity:     SeverityHigh,
			File:         file,
			Line:         line,
			Column:       col,
			Evidence:     truncateStr(evidence, 180),
			WhyItMatters: truncateStr(firstNonEmpty(meta.Details, "govulncheck found a reachable vulnerable Go module or standard library symbol."), 500),
			Remediation:  remediation,
		})
	}
	return findings, nil
}

func bestGovulnFrame(trace []govulnFrame) govulnFrame {
	for _, frame := range trace {
		if frame.Position.Filename != "" {
			return frame
		}
	}
	if len(trace) > 0 {
		return trace[len(trace)-1]
	}
	return govulnFrame{}
}

func govulnEvidence(v govulnFinding, meta govulnOSV, frame govulnFrame) string {
	parts := []string{v.OSV}
	if len(meta.Aliases) > 0 {
		parts = append(parts, strings.Join(meta.Aliases, ", "))
	}
	if frame.Module != "" {
		parts = append(parts, "module="+frame.Module)
	}
	if frame.Package != "" {
		parts = append(parts, "package="+frame.Package)
	}
	if frame.Function != "" {
		parts = append(parts, "function="+frame.Function)
	}
	return strings.Join(parts, " | ")
}

func normalizeExternalRuleID(prefix, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		id = "UNKNOWN"
	}
	id = strings.NewReplacer("/", "-", ".", "-", " ", "-", "_", "-").Replace(id)
	return strings.ToUpper(prefix + "-" + id)
}

func externalSeverity(raw string) Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func parsePositiveInt(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func absoluteFindingPath(root, p string) string {
	p = strings.TrimSpace(filepath.FromSlash(p))
	if p == "" {
		return root
	}
	if filepath.IsAbs(p) {
		return p
	}
	if abs, err := filepath.Abs(filepath.Join(root, p)); err == nil {
		return abs
	}
	return filepath.Join(root, p)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
