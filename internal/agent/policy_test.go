package agent

import (
	"testing"

	"vulnscanner/internal/scanner"
)

func TestShouldFailByPolicy(t *testing.T) {
	report := Report{
		Findings: []FindingWithVerdict{
			{
				Finding: scanner.Finding{Severity: scanner.SeverityHigh},
				Verdict: Verdict{Label: VerdictTruePositive},
			},
		},
	}
	if !ShouldFail(report, ExitPolicy{
		FailOnSeverity: scanner.SeverityMedium,
		FailOnVerdict:  VerdictTruePositive,
	}) {
		t.Fatal("expected failure by policy")
	}
	if ShouldFail(report, ExitPolicy{
		FailOnSeverity: scanner.SeverityCritical,
		FailOnVerdict:  VerdictTruePositive,
	}) {
		t.Fatal("did not expect failure for higher severity threshold")
	}
}
