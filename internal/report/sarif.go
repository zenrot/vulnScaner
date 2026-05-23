package report

import (
	"encoding/json"
	"io"

	"vulnscanner/internal/agent"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

func WriteSARIF(w io.Writer, report agent.Report) error {
	rulesMap := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(report.Findings))
	for _, item := range report.Findings {
		f := item.Finding
		if _, ok := rulesMap[f.RuleID]; !ok {
			rule := sarifRule{
				ID:   f.RuleID,
				Name: f.Title,
			}
			rule.ShortDescription.Text = f.WhyItMatters
			rulesMap[f.RuleID] = rule
		}
		result := sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(string(f.Severity)),
		}
		result.Message.Text = f.Title + ": " + f.Evidence + " | verdict=" + string(item.Verdict.Label)
		loc := struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine   int `json:"startLine"`
					StartColumn int `json:"startColumn"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region.StartLine = f.Line
		loc.PhysicalLocation.Region.StartColumn = f.Column
		result.Locations = []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine   int `json:"startLine"`
					StartColumn int `json:"startColumn"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}{loc}
		results = append(results, result)
	}
	rules := make([]sarifRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:  "vulnscanner",
						Rules: rules,
					},
				},
				Results: results,
			},
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}
