package gigachat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/agent/provider"
)

const (
	oauthURL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
	apiBase  = "https://gigachat.devices.sberbank.ru/api/v1"
)

var transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

type Backend struct {
	AuthKey string
	Model   string
	Scope   string
	cache   tokenCache
}

type tokenCache struct {
	mu      sync.Mutex
	token   string
	tokenEx time.Time
}

func New(radius int, authKey, model, scope string) agent.TriageProvider {
	return &provider.SingleProvider{Backend: &Backend{AuthKey: authKey, Model: model, Scope: scope}, Radius: radius}
}

func NewAgentic(radius int, authKey, model, scope string) agent.TriageProvider {
	return &provider.AgenticProvider{Backend: &Backend{AuthKey: authKey, Model: model, Scope: scope}, Radius: radius}
}

func (b *Backend) Name() string { return "gigachat:" + b.Model }

func (b *Backend) Complete(ctx context.Context, prompt string, _ bool) (string, error) {
	token, err := b.cache.getToken(ctx, b.AuthKey, b.Scope)
	if err != nil {
		return "", err
	}
	return complete(ctx, token, b.Model, prompt)
}

func (c *tokenCache) getToken(ctx context.Context, authKey, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenEx.Add(-2*time.Minute)) {
		return c.token, nil
	}
	if scope == "" {
		scope = "GIGACHAT_API_PERS"
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthURL, strings.NewReader("scope="+scope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("RqUID", randomUID())
	req.Header.Set("Authorization", "Basic "+authKey)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gigachat oauth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("gigachat oauth (%s): %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("gigachat oauth decode: %w", err)
	}
	c.token = result.AccessToken
	if result.ExpiresAt > 0 {
		c.tokenEx = time.UnixMilli(result.ExpiresAt)
	} else {
		c.tokenEx = time.Now().Add(25 * time.Minute)
	}
	return c.token, nil
}

func complete(ctx context.Context, accessToken, model, prompt string) (string, error) {
	reqBody := map[string]any{
		"model":       model,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"temperature": 0.1,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Minute, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gigachat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("gigachat API (%s): %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("gigachat decode: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("gigachat: empty response (no choices)")
	}
	return result.Choices[0].Message.Content, nil
}

func randomUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
