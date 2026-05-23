package scanner

type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	RuleID       string   `json:"rule_id"`
	Title        string   `json:"title"`
	Severity     Severity `json:"severity"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Column       int      `json:"column"`
	Evidence     string   `json:"evidence"`
	WhyItMatters string   `json:"why_it_matters"`
	Remediation  string   `json:"remediation"`
}
