package provider

import (
	"context"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/logging"
	"vulnscanner/internal/scanner"
)

type SingleProvider struct {
	Backend LLMBackend
	Radius  int
}

func (s *SingleProvider) Name() string { return s.Backend.Name() }

func (s *SingleProvider) Triage(ctx context.Context, finding scanner.Finding) (agent.Verdict, error) {
	return retryTriage(ctx, func() (agent.Verdict, error) {
		enr := agent.GetEnrichment(ctx)
		snippet := agent.SnippetAround(finding.File, finding.Line, s.Radius)
		raw, err := s.Backend.Complete(ctx, buildPrompt(finding, snippet, enr.CWEContext, enr.Examples), true)
		if err != nil {
			return agent.Verdict{}, err
		}
		v, err := parseVerdict(raw, s.Name(), finding.Remediation)
		if err != nil {
			logging.L().Warn("single provider verdict parse failed",
				"provider", s.Name(),
				"rule_id", finding.RuleID,
				"file", finding.File,
				"line", finding.Line,
				"raw", truncateForLog(raw, 500),
				"err", err,
			)
			return agent.Verdict{}, err
		}
		logging.L().Debug("single provider verdict parsed",
			"provider", s.Name(),
			"rule_id", finding.RuleID,
			"label", v.Label,
			"confidence", v.Confidence,
		)
		return v, nil
	})
}
