package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/agent/provider"
)

type Backend struct {
	BaseURL string
	Model   string
	NumCtx  int
	client  *http.Client
}

func New(radius int, baseURL, model string, numCtx int) agent.TriageProvider {
	return &provider.SingleProvider{Backend: &Backend{BaseURL: baseURL, Model: model, NumCtx: numCtx}, Radius: radius}
}

func NewAgentic(radius int, baseURL, model string, numCtx int) agent.TriageProvider {
	return &provider.AgenticProvider{Backend: &Backend{BaseURL: baseURL, Model: model, NumCtx: numCtx}, Radius: radius}
}

func (b *Backend) Name() string { return "ollama:" + b.Model }

func (b *Backend) Complete(ctx context.Context, prompt string, jsonMode bool) (string, error) {
	client := b.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	url := b.BaseURL
	if url == "" {
		url = "http://127.0.0.1:11434"
	}
	reqBody := map[string]any{"model": b.Model, "stream": false, "prompt": prompt}
	if jsonMode {
		reqBody["format"] = "json"
	}
	if b.NumCtx > 0 {
		reqBody["options"] = map[string]any{"num_ctx": b.NumCtx}
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", ollamaHTTPError(resp)
	}
	var raw struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}
	return raw.Response, nil
}

func ollamaHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	if len(body) > 0 && json.Unmarshal(body, &e) == nil && e.Error != "" {
		return fmt.Errorf("ollama error: %s", e.Error)
	}
	if len(body) > 0 {
		return fmt.Errorf("ollama %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return fmt.Errorf("ollama response status: %s", resp.Status)
}
