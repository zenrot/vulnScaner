package provider

import "context"

type LLMBackend interface {
	Name() string
	Complete(ctx context.Context, prompt string, jsonMode bool) (string, error)
}
