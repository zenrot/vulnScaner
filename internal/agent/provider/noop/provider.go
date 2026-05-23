package noop

import (
	"context"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/scanner"
)

type Provider struct{}

func New() agent.TriageProvider {
	return Provider{}
}

func (n Provider) Name() string { return "noop" }

func (n Provider) Triage(_ context.Context, finding scanner.Finding) (agent.Verdict, error) {
	label := agent.VerdictNeedsReview
	confidence := 0.65
	if finding.Severity == scanner.SeverityHigh || finding.Severity == scanner.SeverityCritical {
		label = agent.VerdictTruePositive
		confidence = 0.8
	}
	return agent.Verdict{
		Label:       label,
		Confidence:  confidence,
		Rationale:   "Verdict based on rule severity.",
		Remediation: finding.Remediation,
		Provider:    n.Name(),
	}, nil
}
