package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/agent/provider"
)

const defaultBaseURL = "https://api.openai.com/v1"

type Backend struct {
	BaseURL string
	APIKey  string
	Model   string
	client  *http.Client
}

func New(radius int, baseURL, apiKey, model string) agent.TriageProvider {
	return &provider.SingleProvider{Backend: &Backend{BaseURL: baseURL, APIKey: apiKey, Model: model}, Radius: radius}
}

func NewAgentic(radius int, baseURL, apiKey, model string) agent.TriageProvider {
	return &provider.AgenticProvider{Backend: &Backend{BaseURL: baseURL, APIKey: apiKey, Model: model}, Radius: radius}
}

func (b *Backend) Name() string { return "openai:" + b.Model }

func (b *Backend) Complete(ctx context.Context, prompt string, jsonMode bool) (string, error) {
	client := b.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	base := b.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	reqBody := map[string]any{
		"model":       b.Model,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"temperature": 0.1,
	}
	if jsonMode {
		reqBody["response_format"] = map[string]string{"type": "json_object"}
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", openAIHTTPError(resp)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("openai: decode response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response (no choices)")
	}
	return result.Choices[0].Message.Content, nil
}

func openAIHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if len(body) > 0 && json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("openai error (%s): %s", resp.Status, e.Error.Message)
	}
	return fmt.Errorf("openai response status: %s", resp.Status)
}
