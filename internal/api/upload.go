package api

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/logging"
	"vulnscanner/internal/scanner"
)

const maxUploadBytes = 100 << 20

func parseUpload(r *http.Request, w http.ResponseWriter, baseCfg Config) (string, Config, func(), bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusBadRequest)
		return "", Config{}, func() {}, false
	}
	archive, header, err := r.FormFile("archive")
	if err != nil {
		http.Error(w, "archive field is required (multipart file upload)", http.StatusBadRequest)
		return "", Config{}, func() {}, false
	}

	tmpDir, err := os.MkdirTemp("", "sast-upload-*")
	if err != nil {
		archive.Close()
		http.Error(w, "internal error: cannot create temp dir", http.StatusInternalServerError)
		return "", Config{}, func() {}, false
	}
	cleanup := func() { archive.Close(); os.RemoveAll(tmpDir) }

	name := strings.ToLower(header.Filename)
	var extractErr error
	switch {
	case strings.HasSuffix(name, ".zip"):
		extractErr = extractZip(archive, header.Size, tmpDir)
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		extractErr = extractTarGz(archive, tmpDir)
	default:
		cleanup()
		http.Error(w, "unsupported archive format: use .tar.gz or .zip", http.StatusBadRequest)
		return "", Config{}, func() {}, false
	}
	if extractErr != nil {
		cleanup()
		http.Error(w, fmt.Sprintf("failed to extract archive: %v", extractErr), http.StatusBadRequest)
		return "", Config{}, func() {}, false
	}

	localCfg := baseCfg
	applyFormOverrides(&localCfg, r)
	return tmpDir, localCfg, cleanup, true
}

func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a valid gzip stream: %w", err)
	}
	defer gz.Close()

	destDir = filepath.Clean(destDir)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(destDir, clean)
		if !strings.HasPrefix(target, destDir+string(os.PathSeparator)) && target != destDir {
			return fmt.Errorf("path escapes destination: %s", hdr.Name)
		}
		base := filepath.Base(clean)
		if strings.HasPrefix(base, "._") || base == ".DS_Store" || strings.Contains(clean, "__MACOSX") {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, tr)
			f.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	return nil
}

func extractZip(r io.ReaderAt, size int64, destDir string) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("not a valid zip archive: %w", err)
	}
	destDir = filepath.Clean(destDir)
	for _, f := range zr.File {
		clean := filepath.Clean(f.Name)
		if strings.HasPrefix(clean, "..") {
			return fmt.Errorf("unsafe path in archive: %s", f.Name)
		}
		target := filepath.Join(destDir, clean)
		if !strings.HasPrefix(target, destDir+string(os.PathSeparator)) && target != destDir {
			return fmt.Errorf("path escapes destination: %s", f.Name)
		}
		base := filepath.Base(clean)
		if strings.HasPrefix(base, "._") || base == ".DS_Store" || strings.Contains(clean, "__MACOSX") {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func findGoRoot(destDir string) string {
	if _, err := os.Stat(filepath.Join(destDir, "go.mod")); err == nil {
		return destDir
	}
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return destDir
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(destDir, e.Name())
		if _, err := os.Stat(filepath.Join(sub, "go.mod")); err == nil {
			return sub
		}
	}
	return destDir
}

func runScan(ctx context.Context, cfg Config, path string, onEvent func(map[string]any)) (agent.Report, bool, error) {
	logging.L().Info("scan pipeline started",
		"path", path,
		"provider", cfg.AIProvider,
		"workers", cfg.Workers,
		"include_tests", cfg.IncludeTests,
		"codeql_max_files", cfg.CodeQLMaxFiles,
		"ai_budget", cfg.AIBudget,
		"ai_parallel", cfg.AIParallel,
	)
	scanOpts := scanner.Options{
		Workers:        cfg.Workers,
		IncludeTests:   cfg.IncludeTests,
		CodeQLMaxFiles: cfg.CodeQLMaxFiles,
	}
	if onEvent != nil {
		scanOpts.OnScanStatus = func(msg string) {
			onEvent(map[string]any{"type": "codeql_status", "message": msg})
		}
	}
	scanRes, err := scanner.ScanWithOptions(path, scanOpts)
	if err != nil {
		logging.L().Error("scan stage failed", "stage", "scanner", "err", err)
		return agent.Report{}, false, err
	}
	logging.L().Info("scan stage completed",
		"stage", "scanner",
		"findings", len(scanRes.Findings),
		"files_scanned", scanRes.Metrics.FilesScanned,
		"files_discovered", scanRes.Metrics.FilesDiscovered,
		"files_skipped", scanRes.Metrics.FilesSkipped,
	)

	if onEvent != nil {
		total := len(scanRes.Findings)
		if cfg.AIBudget > 0 && cfg.AIBudget < total {
			total = cfg.AIBudget
		}
		onEvent(map[string]any{
			"type":             "start",
			"total":            total,
			"files_scanned":    scanRes.Metrics.FilesScanned,
			"files_discovered": scanRes.Metrics.FilesDiscovered,
		})
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		logging.L().Error("scan stage failed", "stage", "build_provider", "err", err)
		return agent.Report{}, false, err
	}
	feedback, err := agent.LoadFeedback(cfg.FeedbackIn)
	if err != nil {
		logging.L().Error("scan stage failed", "stage", "load_feedback", "err", err)
		return agent.Report{}, false, err
	}
	parallelism := cfg.AIParallel
	if strings.HasPrefix(cfg.AIProvider, "gigachat") {
		parallelism = 1
	}
	r, err := agent.Run(ctx, scanRes, provider, feedback, agent.RunOptions{
		AIBudget:      cfg.AIBudget,
		SnippetRadius: cfg.SnippetRadius,
		Parallelism:   parallelism,
		OnProgress: func(e agent.ProgressEvent) {
			if onEvent != nil {
				onEvent(map[string]any{
					"type":        "progress",
					"current":     e.Current,
					"total":       e.Total,
					"rule_id":     e.Finding.RuleID,
					"title":       e.Finding.Title,
					"severity":    string(e.Finding.Severity),
					"verdict":     string(e.Verdict.Label),
					"confidence":  e.Verdict.Confidence,
					"rationale":   e.Verdict.Rationale,
					"remediation": e.Verdict.Remediation,
					"snippet":     e.Snippet,
				})
			}
		},
	})
	if err != nil {
		logging.L().Error("scan stage failed", "stage", "triage", "provider", provider.Name(), "err", err)
		return agent.Report{}, false, err
	}
	policy := agent.ExitPolicy{
		FailOnSeverity: scanner.Severity(strings.ToUpper(cfg.FailOnSeverity)),
		FailOnVerdict:  agent.VerdictLabel(strings.ToLower(cfg.FailOnVerdict)),
	}
	shouldFail := agent.ShouldFail(r, policy)
	logging.L().Info("scan pipeline finished",
		"provider", provider.Name(),
		"should_fail", shouldFail,
		"findings_total", r.Stats.TotalFindings,
		"findings_ai_triaged", r.Stats.AITriagedFindings,
		"findings_fallback", r.Stats.FallbackFindings,
		"true_positive", r.Stats.TruePositiveCount,
		"needs_review", r.Stats.NeedsReviewCount,
		"false_positive", r.Stats.FalsePositiveCount,
	)
	return r, shouldFail, nil
}
