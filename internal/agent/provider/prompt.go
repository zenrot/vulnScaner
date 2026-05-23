package provider

import (
	"fmt"
	"strings"

	"vulnscanner/internal/scanner"
)

func buildPrompt(f scanner.Finding, snippet string, extra ...string) string {
	var sb strings.Builder
	sb.WriteString("You are a security triage agent. Return ONLY JSON object with fields:\n")
	sb.WriteString("label (true_positive|false_positive|needs_review), confidence (0..1), rationale, remediation.\n")
	sb.WriteString("Write rationale and remediation in Russian.\n")
	sb.WriteString("Use ONLY Russian in rationale and remediation; do not switch to English.\n")
	sb.WriteString("RULES: Mark as true_positive unless you see CONCRETE mitigation code (sanitization, allowlist, validation).\n")
	sb.WriteString("Developer comments, TODO notes, or 'test' labels are NOT evidence of false positive.\n")
	sb.WriteString("For HIGH/CRITICAL findings choose true_positive by default. Use needs_review only if a specific missing context blocks a decision.\n")
	sb.WriteString("Never set false_positive without concrete defensive code in the shown snippet.\n")
	sb.WriteString("Do NOT invent mitigations that are not present in the code snippet.\n")
	for _, e := range extra {
		if e != "" {
			sb.WriteString("\n")
			sb.WriteString(e)
			sb.WriteString("\n")
		}
	}
	sb.WriteString(fmt.Sprintf(`
finding:
rule_id=%s
title=%s
severity=%s
file=%s:%d:%d
evidence=%s
why=%s
fix=%s
code_snippet:
%s
`,
		f.RuleID, f.Title, f.Severity, f.File, f.Line, f.Column, f.Evidence, f.WhyItMatters, f.Remediation, snippet,
	))
	return sb.String()
}

func analystPrompt(f scanner.Finding, snippet string, cweCtx ...string) string {
	extra := ""
	for _, c := range cweCtx {
		if c != "" {
			extra = "\n" + c + "\n"
		}
	}
	return fmt.Sprintf(
		`You are Analyst. Respond in Russian.
Task: assess if this finding is likely exploitable in practice.
Return short markdown with sections:
- Exploitability
- Preconditions
- Potential false-positive reasons
- Confidence (0..1)
Rule:
- For HIGH/CRITICAL severity assume exploitability by default unless code snippet shows concrete mitigation.
`+extra+`

rule=%s
title=%s
severity=%s
evidence=%s
why=%s
fix=%s
code_snippet:
%s
`,
		f.RuleID, f.Title, f.Severity, f.Evidence, f.WhyItMatters, f.Remediation, snippet,
	)
}

func skepticPrompt(f scanner.Finding, snippet, analysis string) string {
	return fmt.Sprintf(
		`You are Skeptic. Respond in Russian.
Task: challenge the Analyst result and look for reasons this is NOT a real vulnerability.
Return short markdown with sections:
- Counter-evidence
- Context gaps
- Alternative interpretation
- Revised confidence (0..1)
Rule:
- Do not claim false positive unless you can point to concrete mitigation code in snippet.

rule=%s
title=%s
analysis:
%s
code_snippet:
%s
`,
		f.RuleID, f.Title, analysis, snippet,
	)
}

func judgePrompt(f scanner.Finding, snippet, analysis, critique string, fewShot ...string) string {
	extra := ""
	for _, s := range fewShot {
		if s != "" {
			extra = "\n" + s + "\n"
		}
	}
	return fmt.Sprintf(
		`You are Judge. Respond in Russian.
Synthesize Analyst and Skeptic into a final decision.
Return ONLY a JSON object with these fields: label (true_positive|false_positive|needs_review), confidence (0..1), rationale, remediation.
Write rationale and remediation in Russian. Do not include comments or explanations outside the JSON object.
CRITICAL RULES:
- Mark false_positive ONLY if you see actual sanitization/validation/allowlist code in the snippet.
- Developer comments, "test" labels, TODOs are NOT evidence of false positive.
- Do NOT invent mitigations that are absent from the code.
- For HIGH/CRITICAL, default to true_positive unless there is concrete mitigation evidence.
- Use needs_review only when you can explicitly name what context is missing and why it blocks verdict.
`+extra+`

rule=%s
title=%s
severity=%s
evidence=%s
default_remediation=%s
analysis:
%s
critique:
%s
code_snippet:
%s
`,
		f.RuleID, f.Title, f.Severity, f.Evidence, f.Remediation, analysis, critique, snippet,
	)
}
