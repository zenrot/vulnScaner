package provider

import (
	"context"
	"strings"
	"time"

	"vulnscanner/internal/agent"
)

const (
	retryDelay     = 2 * time.Second
	rateLimitDelay = 5 * time.Second
)

func retryTriage(ctx context.Context, fn func() (agent.Verdict, error)) (agent.Verdict, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := retryDelay
			if lastErr != nil {
				s := strings.ToLower(lastErr.Error())
				if strings.Contains(s, "429") || strings.Contains(s, "too many requests") || strings.Contains(s, "rate limit") {
					delay = rateLimitDelay
				}
			}
			select {
			case <-ctx.Done():
				return agent.Verdict{}, ctx.Err()
			case <-time.After(delay):
			}
		}
		v, err := fn()
		if err == nil {
			return v, nil
		}
		lastErr = err
		if !isTransientError(err) {
			break
		}
	}
	return agent.Verdict{}, lastErr
}

func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unexpected eof") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, " eof") ||
		strings.Contains(s, "429") ||
		strings.Contains(s, "too many requests") ||
		strings.Contains(s, "rate limit")
}
