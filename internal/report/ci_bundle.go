package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnscanner/internal/agent"
)

func WriteCIBundle(dir string, r agent.Report, shouldFail bool) error {
	if dir == "" {
		return fmt.Errorf("ci output dir is empty")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	jf, err := os.Create(filepath.Join(dir, "report.json"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(jf)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(r); encErr != nil {
		_ = jf.Close()
		return encErr
	}
	_ = jf.Close()

	sf, err := os.Create(filepath.Join(dir, "report.sarif"))
	if err != nil {
		return err
	}
	if sarifErr := WriteSARIF(sf, r); sarifErr != nil {
		_ = sf.Close()
		return sarifErr
	}
	_ = sf.Close()

	return os.WriteFile(filepath.Join(dir, "summary.md"), []byte(buildSummary(r, shouldFail)), 0644)
}

func buildSummary(r agent.Report, shouldFail bool) string {
	var b strings.Builder

	status := "🟢 PASS"
	if shouldFail {
		status = "🔴 FAIL"
	}

	b.WriteString("## 🔒 Отчёт SAST\n\n")
	b.WriteString("<!-- sast-bot -->\n\n")

	b.WriteString("| | |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| **Статус** | %s |\n", status))
	b.WriteString(fmt.Sprintf("| **Файлов просканировано** | %d |\n", r.ScanMetrics.FilesScanned))
	b.WriteString(fmt.Sprintf("| **Всего находок** | %d |\n", r.Stats.TotalFindings))
	b.WriteString(fmt.Sprintf("| **Проверено** | %d |\n", r.Stats.AITriagedFindings))
	b.WriteString(fmt.Sprintf("| **Реальные** | %d |\n", r.Stats.TruePositiveCount))
	b.WriteString(fmt.Sprintf("| **На проверку** | %d |\n", r.Stats.NeedsReviewCount))
	b.WriteString(fmt.Sprintf("| **Ложные** | %d |\n", r.Stats.FalsePositiveCount))
	if r.Stats.FeedbackOverrides > 0 {
		b.WriteString(fmt.Sprintf("| **Переопределено feedback** | %d |\n", r.Stats.FeedbackOverrides))
	}
	b.WriteString("\n")

	var actionable []agent.FindingWithVerdict
	for _, item := range r.Findings {
		l := item.Verdict.Label
		if l == agent.VerdictTruePositive || l == agent.VerdictNeedsReview {
			actionable = append(actionable, item)
		}
	}

	if len(actionable) == 0 {
		b.WriteString("Уязвимостей, требующих внимания, не обнаружено.\n")
	} else {
		b.WriteString("### Находки\n\n")
		limit := len(actionable)
		if limit > 20 {
			limit = 20
		}
		for _, item := range actionable[:limit] {
			f := item.Finding
			v := item.Verdict

			icon := severityIcon(string(f.Severity))
			file := filepath.Base(f.File)

			b.WriteString(fmt.Sprintf("<details>\n<summary>%s %s · %s · %s (%s:%d)</summary>\n\n",
				icon, f.Severity, v.Label, f.Title, file, f.Line))

			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf("**Свидетельство:** `%s`\n\n", f.Evidence))
			}
			if v.Rationale != "" {
				b.WriteString(fmt.Sprintf("**Вердикт:** %s\n\n", v.Rationale))
			}
			if v.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Исправление:** %s\n\n", v.Remediation))
			}
			if item.Snippet != "" {
				b.WriteString("```go\n")
				b.WriteString(item.Snippet)
				b.WriteString("\n```\n\n")
			}
			b.WriteString("</details>\n")
		}
		if len(actionable) > 20 {
			b.WriteString(fmt.Sprintf("\n*…и ещё %d находок. Смотри report.json.*\n", len(actionable)-20))
		}
	}

	b.WriteString(fmt.Sprintf("\n---\n*Сгенерировано: %s*\n", time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	return b.String()
}

func severityIcon(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	default:
		return "🔵"
	}
}
