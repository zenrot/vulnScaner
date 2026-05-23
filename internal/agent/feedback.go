package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"vulnscanner/internal/scanner"
)

type FeedbackRecord struct {
	Key      string       `json:"key"`
	Decision VerdictLabel `json:"decision"`
	Comment  string       `json:"comment,omitempty"`
	RuleID   string       `json:"rule_id,omitempty"`
	Title    string       `json:"title,omitempty"`
	Severity string       `json:"severity,omitempty"`
	Evidence string       `json:"evidence,omitempty"`
	Snippet  string       `json:"snippet,omitempty"`
}

type FeedbackSet struct {
	Records []FeedbackRecord `json:"records"`
}

func findingKey(f scanner.Finding) string {
	return f.RuleID + "|" + f.File + "|" + strconv.Itoa(f.Line)
}

func LoadFeedback(path string) (map[string]FeedbackRecord, error) {
	if path == "" {
		return map[string]FeedbackRecord{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]FeedbackRecord{}, nil
		}
		return nil, err
	}
	var set FeedbackSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	out := make(map[string]FeedbackRecord, len(set.Records))
	for _, record := range set.Records {
		out[record.Key] = record
	}
	return out, nil
}

func WriteFeedbackCandidates(path string, findings []scanner.Finding) error {
	if path == "" {
		return nil
	}
	set := FeedbackSet{Records: make([]FeedbackRecord, 0, len(findings))}
	for _, f := range findings {
		set.Records = append(set.Records, FeedbackRecord{
			Key:      findingKey(f),
			Decision: VerdictNeedsReview,
			RuleID:   f.RuleID,
			Title:    f.Title,
			Severity: string(f.Severity),
			Evidence: f.Evidence,
			Snippet:  SnippetAround(f.File, f.Line, 4),
		})
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func ApplyFeedback(verdict Verdict, finding scanner.Finding, feedback map[string]FeedbackRecord) Verdict {
	record, ok := feedback[findingKey(finding)]
	if !ok {
		return verdict
	}
	verdict.Label = record.Decision
	verdict.Confidence = 0.95
	if record.Comment != "" {
		verdict.Rationale = "Reviewer feedback: " + record.Comment
	} else {
		verdict.Rationale = "Reviewer feedback override"
	}
	verdict.Provider = verdict.Provider + "+feedback"
	return verdict
}

func GetExamples(f scanner.Finding, feedback map[string]FeedbackRecord, n int) string {
	if len(feedback) == 0 || n <= 0 {
		return ""
	}

	type scored struct {
		rec   FeedbackRecord
		score int
	}
	var candidates []scored
	for _, rec := range feedback {
		if rec.Decision == VerdictNeedsReview {
			continue
		}
		s := 0
		if rec.RuleID == f.RuleID {
			s += 2
		}
		if rec.Severity == string(f.Severity) {
			s += 1
		}
		if s > 0 || len(candidates) < n {
			candidates = append(candidates, scored{rec, s})
		}
	}
	if len(candidates) == 0 {
		return ""
	}

	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}
	if len(candidates) > n {
		candidates = candidates[:n]
	}

	var sb strings.Builder
	sb.WriteString("Verified examples for reference:\n")
	for i, c := range candidates {
		r := c.rec
		sb.WriteString(fmt.Sprintf(
			"Example %d: Rule=%s Title=%q Severity=%s Evidence=%q\n"+
				"  Decision: %s\n",
			i+1, r.RuleID, r.Title, r.Severity, r.Evidence, strings.ToUpper(string(r.Decision)),
		))
		if r.Comment != "" {
			sb.WriteString(fmt.Sprintf("  Reasoning: %s\n", r.Comment))
		}
	}
	return sb.String()
}
