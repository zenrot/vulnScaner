package agent

import (
	"testing"

	"vulnscanner/internal/scanner"
)

func TestCalibrateVerdict_HighRiskNeedsReviewToTruePositive(t *testing.T) {
	f := scanner.Finding{
		RuleID:   "GO-CMD-SHELL",
		Severity: scanner.SeverityHigh,
		File:     "/tmp/main.go",
	}
	v := Verdict{Label: VerdictNeedsReview, Confidence: 0.42}
	got, changed, _ := calibrateVerdict(f, v, `exec.Command("sh", "-c", "ping -c 1 "+host)`)
	if !changed {
		t.Fatalf("expected changed verdict")
	}
	if got.Label != VerdictTruePositive {
		t.Fatalf("expected true_positive, got %s", got.Label)
	}
}

func TestCalibrateVerdict_MediumNeedsReviewStaysNeedsReview(t *testing.T) {
	f := scanner.Finding{
		RuleID:   "GO-RAND-INSECURE",
		Severity: scanner.SeverityMedium,
		File:     "/tmp/main.go",
	}
	v := Verdict{Label: VerdictNeedsReview, Confidence: 0.5}
	got, _, _ := calibrateVerdict(f, v, `rand.Int63()`)
	if got.Label != VerdictNeedsReview {
		t.Fatalf("expected needs_review, got %s", got.Label)
	}
}

func TestCalibrateVerdict_FalsePositiveWithoutMitigationToNeedsReview(t *testing.T) {
	f := scanner.Finding{
		RuleID:   "GO-HARDCODED-SECRET",
		Severity: scanner.SeverityHigh,
		File:     "/tmp/main.go",
	}
	v := Verdict{Label: VerdictFalsePositive, Confidence: 0.2}
	got, changed, _ := calibrateVerdict(f, v, `const apiToken = "Bearer eyJ..."`)
	if !changed {
		t.Fatalf("expected changed verdict")
	}
	if got.Label != VerdictNeedsReview {
		t.Fatalf("expected needs_review, got %s", got.Label)
	}
}

func TestCalibrateVerdict_FalsePositiveWithMitigationStaysFalsePositive(t *testing.T) {
	f := scanner.Finding{
		RuleID:   "GO-PATH-TRAVERSAL-TAINT",
		Severity: scanner.SeverityHigh,
		File:     "/tmp/main.go",
	}
	v := Verdict{Label: VerdictFalsePositive, Confidence: 0.8}
	got, _, _ := calibrateVerdict(f, v, `safe := filepath.Clean(userPath)`)
	if got.Label != VerdictFalsePositive {
		t.Fatalf("expected false_positive, got %s", got.Label)
	}
}
