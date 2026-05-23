package agent

import (
	"strings"

	"vulnscanner/internal/scanner"
)

func calibrateVerdict(f scanner.Finding, v Verdict, snippet string) (Verdict, bool, string) {
	original := v
	v.Label = normalizeLabel(v.Label)
	v.Confidence = clamp01(v.Confidence)
	if v.Remediation == "" {
		v.Remediation = f.Remediation
	}

	highRisk := f.Severity == scanner.SeverityHigh || f.Severity == scanner.SeverityCritical || isHighRiskRule(f.RuleID)
	mitigated := hasConcreteMitigationEvidence(f.RuleID, snippet)
	testLike := isTestLikePath(f.File)

	switch v.Label {
	case VerdictFalsePositive:
		if !mitigated && !testLike {
			if highRisk {
				v.Label = VerdictTruePositive
				v.Confidence = maxFloat(v.Confidence, 0.78)
				v.Rationale = appendNote(v.Rationale, "Автокалибровка: для HIGH/CRITICAL без явной защиты помечено как true_positive.")
				return v, verdictChanged(original, v), "false_positive_without_mitigation_high_risk"
			}
			v.Label = VerdictNeedsReview
			v.Confidence = maxFloat(v.Confidence, 0.55)
			v.Rationale = appendNote(v.Rationale, "Автокалибровка: нет явной защиты в сниппете, требуется проверка.")
			return v, verdictChanged(original, v), "false_positive_without_mitigation"
		}
	case VerdictNeedsReview:
		if highRisk && !mitigated && hasStrongRiskSignal(f, snippet) && !testLike {
			v.Label = VerdictTruePositive
			v.Confidence = maxFloat(v.Confidence, 0.74)
			v.Rationale = appendNote(v.Rationale, "Автокалибровка: обнаружены признаки эксплуатируемого HIGH/CRITICAL сценария.")
			return v, verdictChanged(original, v), "needs_review_to_true_positive_high_risk"
		}
	}

	return v, verdictChanged(original, v), "normalized"
}

func verdictChanged(before, after Verdict) bool {
	return before.Label != after.Label || before.Confidence != after.Confidence || before.Remediation != after.Remediation || before.Rationale != after.Rationale
}

func normalizeLabel(label VerdictLabel) VerdictLabel {
	switch strings.ToLower(strings.TrimSpace(string(label))) {
	case "true_positive", "truepositive", "tp", "real", "real_vuln":
		return VerdictTruePositive
	case "false_positive", "falsepositive", "fp":
		return VerdictFalsePositive
	case "needs_review", "need_review", "review":
		return VerdictNeedsReview
	default:
		return VerdictNeedsReview
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func appendNote(rationale, note string) string {
	rationale = strings.TrimSpace(rationale)
	if rationale == "" {
		return note
	}
	if strings.Contains(rationale, note) {
		return rationale
	}
	return rationale + " " + note
}

func isHighRiskRule(ruleID string) bool {
	switch strings.ToUpper(strings.TrimSpace(ruleID)) {
	case "GO-CMD-SHELL",
		"GO-CMD-INJECTION-TAINT",
		"GO-SSRF-TAINT",
		"GO-PATH-TRAVERSAL-TAINT",
		"GO-TLS-SKIP-VERIFY",
		"GO-HARDCODED-SECRET",
		"GO-CRYPTO-WEAK":
		return true
	default:
		return false
	}
}

func hasConcreteMitigationEvidence(ruleID, snippet string) bool {
	s := strings.ToLower(snippet)
	switch strings.ToUpper(strings.TrimSpace(ruleID)) {
	case "GO-CMD-SHELL", "GO-CMD-INJECTION-TAINT":
		return strings.Contains(s, "allowlist") || strings.Contains(s, "whitelist") || strings.Contains(s, "regexp") || strings.Contains(s, "filepath.clean")
	case "GO-SSRF-TAINT":
		return strings.Contains(s, "allowlist") || strings.Contains(s, "whitelist") || strings.Contains(s, "url.parse") || strings.Contains(s, "net.parseip")
	case "GO-PATH-TRAVERSAL-TAINT":
		return strings.Contains(s, "filepath.clean") || strings.Contains(s, "strings.hasprefix")
	case "GO-TLS-SKIP-VERIFY":
		return strings.Contains(s, "insecureskipverify: false")
	case "GO-RAND-INSECURE":
		return strings.Contains(s, "crypto/rand")
	}
	return strings.Contains(s, "allowlist") ||
		strings.Contains(s, "whitelist") ||
		strings.Contains(s, "sanitize") ||
		strings.Contains(s, "validate(") ||
		strings.Contains(s, "filepath.clean")
}

func hasStrongRiskSignal(f scanner.Finding, snippet string) bool {
	rule := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if strings.HasPrefix(rule, "GO-") {
		switch rule {
		case "GO-CMD-SHELL",
			"GO-CMD-INJECTION-TAINT",
			"GO-SSRF-TAINT",
			"GO-PATH-TRAVERSAL-TAINT",
			"GO-TLS-SKIP-VERIFY",
			"GO-HARDCODED-SECRET":
			return true
		}
	}

	s := strings.ToLower(snippet + "\n" + f.Evidence + "\n" + f.Title)
	return strings.Contains(s, "exec.command(\"sh\"") ||
		strings.Contains(s, "exec.command(\"bash\"") ||
		strings.Contains(s, "insecureskipverify") ||
		strings.Contains(s, "select * from") ||
		strings.Contains(s, " hardcoded ") ||
		strings.Contains(s, "password =") ||
		strings.Contains(s, "token =")
}

func isTestLikePath(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "_test.go") || strings.Contains(p, "/test/") || strings.Contains(p, "/tests/") || strings.Contains(p, "/testdata/")
}
