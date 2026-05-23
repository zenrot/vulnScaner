package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"vulnscanner/internal/logging"
	"vulnscanner/internal/scanner"
)

type VerdictLabel string

const (
	VerdictTruePositive  VerdictLabel = "true_positive"
	VerdictFalsePositive VerdictLabel = "false_positive"
	VerdictNeedsReview   VerdictLabel = "needs_review"
)

type Verdict struct {
	Label       VerdictLabel `json:"label"`
	Confidence  float64      `json:"confidence"`
	Rationale   string       `json:"rationale"`
	Remediation string       `json:"remediation"`
	Provider    string       `json:"provider"`
}

func (v *Verdict) UnmarshalJSON(data []byte) error {
	var raw struct {
		Label       VerdictLabel    `json:"label"`
		Confidence  float64         `json:"confidence"`
		Rationale   json.RawMessage `json:"rationale"`
		Remediation json.RawMessage `json:"remediation"`
		Provider    string          `json:"provider"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	v.Label = raw.Label
	v.Confidence = raw.Confidence
	v.Provider = raw.Provider
	v.Rationale = rawToString(raw.Rationale)
	v.Remediation = rawToString(raw.Remediation)
	return nil
}

func rawToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return strings.Join(arr, " ")
	}
	return strings.TrimSpace(string(raw))
}

type FindingWithVerdict struct {
	Finding scanner.Finding `json:"finding"`
	Verdict Verdict         `json:"verdict"`
	Snippet string          `json:"snippet,omitempty"`
}

type Report struct {
	Findings      []FindingWithVerdict `json:"findings"`
	ScanMetrics   scanner.Metrics      `json:"scan_metrics"`
	AgentDuration time.Duration        `json:"analysis_duration"`
	Stats         Stats                `json:"stats"`
}

type TriageProvider interface {
	Name() string
	Triage(ctx context.Context, finding scanner.Finding) (Verdict, error)
}

type ProgressEvent struct {
	Current int             `json:"current"`
	Total   int             `json:"total"`
	Finding scanner.Finding `json:"finding"`
	Verdict Verdict         `json:"verdict"`
	Snippet string          `json:"snippet,omitempty"`
}

type RunOptions struct {
	AIBudget      int
	SnippetRadius int
	Parallelism   int
	OnProgress    func(ProgressEvent)
}

type Stats struct {
	TotalFindings      int `json:"total_findings"`
	AITriagedFindings  int `json:"ai_triaged_findings"`
	FallbackFindings   int `json:"fallback_findings"`
	FeedbackOverrides  int `json:"feedback_overrides"`
	TruePositiveCount  int `json:"true_positive_count"`
	FalsePositiveCount int `json:"false_positive_count"`
	NeedsReviewCount   int `json:"needs_review_count"`
}

type enrichKey struct{}

type Enrichment struct {
	CWEContext string
	Examples   string
}

func Run(ctx context.Context, scan scanner.Result, provider TriageProvider, feedback map[string]FeedbackRecord, opts RunOptions) (Report, error) {
	if provider == nil {
		return Report{}, errors.New("provider is nil")
	}
	ranked := rankFindings(scan.Findings)
	budget := opts.AIBudget
	if budget <= 0 || budget > len(ranked) {
		budget = len(ranked)
	}

	parallelism := opts.Parallelism
	if parallelism <= 0 {
		parallelism = 1
	}

	start := time.Now()
	stats := Stats{TotalFindings: len(ranked)}

	type triageResult struct {
		idx     int
		finding scanner.Finding
		verdict Verdict
		snippet string
		err     error
	}

	resultCh := make(chan triageResult, budget)
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup

	for i := 0; i < budget; i++ {
		wg.Add(1)
		go func(idx int, f scanner.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			enr := Enrichment{
				CWEContext: GetCWEContext(f.RuleID, f.Title),
				Examples:   GetExamples(f, feedback, 2),
			}
			enrCtx := context.WithValue(ctx, enrichKey{}, enr)

			v, err := provider.Triage(enrCtx, f)
			snip := ""
			if opts.SnippetRadius > 0 {
				snip = SnippetAround(f.File, f.Line, opts.SnippetRadius)
			}
			resultCh <- triageResult{idx, f, v, snip, err}
		}(i, ranked[i])
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	type slot struct {
		finding scanner.Finding
		verdict Verdict
		snippet string
		filled  bool
	}
	slots := make([]slot, budget)
	progressCount := 0

	for r := range resultCh {
		if r.err != nil {
			logging.L().Warn("triage failed",
				"idx", r.idx,
				"rule_id", r.finding.RuleID,
				"file", r.finding.File,
				"line", r.finding.Line,
				"err", r.err,
			)
			r.verdict = Verdict{
				Label:       VerdictNeedsReview,
				Confidence:  0,
				Rationale:   fmt.Sprintf("AI triage failed: %v", r.err),
				Remediation: r.finding.Remediation,
				Provider:    provider.Name(),
			}
			stats.FallbackFindings++
		}
		if r.err == nil {
			if calibrated, changed, reason := calibrateVerdict(r.finding, r.verdict, r.snippet); changed {
				logging.L().Info("verdict auto-calibrated",
					"rule_id", r.finding.RuleID,
					"severity", r.finding.Severity,
					"file", r.finding.File,
					"line", r.finding.Line,
					"from", r.verdict.Label,
					"to", calibrated.Label,
					"reason", reason,
				)
				r.verdict = calibrated
			}
		}
		before := r.verdict.Label
		r.verdict = ApplyFeedback(r.verdict, r.finding, feedback)
		if before != r.verdict.Label {
			stats.FeedbackOverrides++
		}
		if r.err == nil {
			stats.AITriagedFindings++
		}
		switch r.verdict.Label {
		case VerdictTruePositive:
			stats.TruePositiveCount++
		case VerdictFalsePositive:
			stats.FalsePositiveCount++
		default:
			stats.NeedsReviewCount++
		}

		slots[r.idx] = slot{r.finding, r.verdict, r.snippet, true}
		progressCount++

		if opts.OnProgress != nil {
			opts.OnProgress(ProgressEvent{
				Current: progressCount,
				Total:   budget,
				Finding: r.finding,
				Verdict: r.verdict,
				Snippet: r.snippet,
			})
		}
	}

	out := make([]FindingWithVerdict, 0, budget)
	for _, sl := range slots {
		if sl.filled {
			out = append(out, FindingWithVerdict{sl.finding, sl.verdict, sl.snippet})
		}
	}

	return Report{
		Findings:      out,
		ScanMetrics:   scan.Metrics,
		AgentDuration: time.Since(start),
		Stats:         stats,
	}, nil
}

func rankFindings(findings []scanner.Finding) []scanner.Finding {
	ranked := make([]scanner.Finding, len(findings))
	copy(ranked, findings)
	weight := func(s scanner.Severity) int {
		switch s {
		case scanner.SeverityCritical:
			return 4
		case scanner.SeverityHigh:
			return 3
		case scanner.SeverityMedium:
			return 2
		default:
			return 1
		}
	}
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if weight(ranked[j].Severity) > weight(ranked[i].Severity) {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}
	return ranked
}

func GetEnrichment(ctx context.Context) Enrichment {
	enr, _ := ctx.Value(enrichKey{}).(Enrichment)
	return enr
}
