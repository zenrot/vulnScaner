package agent

import "vulnscanner/internal/scanner"

type ExitPolicy struct {
	FailOnSeverity scanner.Severity
	FailOnVerdict  VerdictLabel
}

func ShouldFail(r Report, p ExitPolicy) bool {
	for _, item := range r.Findings {
		if meetsSeverity(item.Finding.Severity, p.FailOnSeverity) && meetsVerdict(item.Verdict.Label, p.FailOnVerdict) {
			return true
		}
	}
	return false
}

func meetsSeverity(got, threshold scanner.Severity) bool {
	if threshold == "" {
		return true
	}
	score := func(s scanner.Severity) int {
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
	return score(got) >= score(threshold)
}

func meetsVerdict(got, threshold VerdictLabel) bool {
	if threshold == "" {
		return got != VerdictFalsePositive
	}
	if threshold == "any" {
		return true
	}
	return got == threshold
}
