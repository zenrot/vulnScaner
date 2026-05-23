package provider

import (
	"encoding/json"
	"fmt"
	"strings"

	"vulnscanner/internal/agent"
)

func parseVerdict(raw, providerName, fallbackRemediation string) (agent.Verdict, error) {
	payload, err := decodeVerdict(raw)
	if err != nil {
		return agent.Verdict{}, fmt.Errorf("cannot decode %s verdict: %w", providerName, err)
	}
	var verdict agent.Verdict
	if err := json.Unmarshal([]byte(payload), &verdict); err != nil {
		return agent.Verdict{}, fmt.Errorf("cannot decode %s verdict: %w", providerName, err)
	}
	verdict.Provider = providerName
	if verdict.Remediation == "" {
		verdict.Remediation = fallbackRemediation
	}
	return verdict, nil
}

func decodeVerdict(raw string) (string, error) {
	if json.Valid([]byte(raw)) {
		return raw, nil
	}
	if obj := extractFirstJSONObject(raw); obj != "" {
		if json.Valid([]byte(obj)) {
			return obj, nil
		}
	}
	if clean := sanitizeJSON(raw); json.Valid([]byte(clean)) {
		return clean, nil
	}
	if obj := extractFirstJSONObject(raw); obj != "" {
		if clean := sanitizeJSON(obj); json.Valid([]byte(clean)) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("no valid JSON found in model response (first 120 chars: %.120s)", raw)
}

func extractFirstJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			continue
		}
		if ch == '{' {
			depth++
		}
		if ch == '}' {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func sanitizeJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	escaped := false
	i := 0
	for i < len(s) {
		c := s[i]
		if escaped {
			escaped = false
			b.WriteByte(c)
			i++
			continue
		}
		if inStr {
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inStr = false
			}
			b.WriteByte(c)
			i++
			continue
		}
		if c == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				i += 2
				for i < len(s) && s[i] != '\n' {
					i++
				}
				continue
			}
			if s[i+1] == '*' {
				i += 2
				for i+1 < len(s) {
					if s[i] == '*' && s[i+1] == '/' {
						i += 2
						break
					}
					i++
				}
				continue
			}
		}
		if c == '"' {
			inStr = true
		}
		b.WriteByte(c)
		i++
	}
	return removeTrailingCommas(b.String())
}

func removeTrailingCommas(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}
