package provider

import (
	"context"
	"strings"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/logging"
	"vulnscanner/internal/scanner"
)

type AgenticProvider struct {
	Backend LLMBackend
	Radius  int
}

func (a *AgenticProvider) Name() string {
	n := a.Backend.Name()
	if idx := strings.IndexByte(n, ':'); idx >= 0 {
		return n[:idx] + "-agentic" + n[idx:]
	}
	return n + "-agentic"
}

func (a *AgenticProvider) Triage(ctx context.Context, finding scanner.Finding) (agent.Verdict, error) {
	return retryTriage(ctx, func() (agent.Verdict, error) {
		enr := agent.GetEnrichment(ctx)
		snippet := agent.SnippetAround(finding.File, finding.Line, a.Radius)

		analysis, err := a.Backend.Complete(ctx, analystPrompt(finding, snippet, enr.CWEContext), false)
		if err != nil {
			return agent.Verdict{}, err
		}
		critique, err := a.Backend.Complete(ctx, skepticPrompt(finding, snippet, analysis), false)
		if err != nil {
			return agent.Verdict{}, err
		}
		judgeRaw, err := a.Backend.Complete(ctx, judgePrompt(finding, snippet, analysis, critique, enr.Examples), true)
		if err != nil {
			return agent.Verdict{}, err
		}
		v, err := parseVerdict(judgeRaw, a.Name(), finding.Remediation)
		if err != nil {
			logging.L().Warn("agentic provider verdict parse failed",
				"provider", a.Name(),
				"rule_id", finding.RuleID,
				"file", finding.File,
				"line", finding.Line,
				"analysis", truncateForLog(analysis, 500),
				"critique", truncateForLog(critique, 500),
				"judge_raw", truncateForLog(judgeRaw, 500),
				"err", err,
			)
			return agent.Verdict{}, err
		}
		logging.L().Debug("agentic provider verdict parsed",
			"provider", a.Name(),
			"rule_id", finding.RuleID,
			"label", v.Label,
			"confidence", v.Confidence,
		)
		return v, nil
	})
}
