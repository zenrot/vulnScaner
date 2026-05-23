package report

import (
	"fmt"
	"io"

	"vulnscanner/internal/agent"
)

func WriteText(w io.Writer, r agent.Report) {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No findings. scanned=%d skipped=%d duration=%s\n", r.ScanMetrics.FilesScanned, r.ScanMetrics.FilesSkipped, r.ScanMetrics.ScanDuration)
		return
	}

	fmt.Fprintf(
		w,
		"Findings: %d | scanned=%d skipped=%d duration=%s analysis_duration=%s\n\n",
		len(r.Findings),
		r.ScanMetrics.FilesScanned,
		r.ScanMetrics.FilesSkipped,
		r.ScanMetrics.ScanDuration,
		r.AgentDuration,
	)
	for _, item := range r.Findings {
		f := item.Finding
		v := item.Verdict
		fmt.Fprintf(w, "[%s] %s (%s)\n", f.Severity, f.Title, f.RuleID)
		fmt.Fprintf(w, "  at %s:%d:%d\n", f.File, f.Line, f.Column)
		fmt.Fprintf(w, "  evidence: %s\n", f.Evidence)
		fmt.Fprintf(w, "  why: %s\n", f.WhyItMatters)
		fmt.Fprintf(w, "  fix: %s\n", f.Remediation)
		fmt.Fprintf(w, "  verdict: label=%s confidence=%.2f provider=%s\n", v.Label, v.Confidence, v.Provider)
		fmt.Fprintf(w, "  rationale: %s\n\n", v.Rationale)
	}
}
