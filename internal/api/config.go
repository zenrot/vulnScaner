package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/agent/provider/gigachat"
	"vulnscanner/internal/agent/provider/noop"
	"vulnscanner/internal/agent/provider/ollama"
	"vulnscanner/internal/agent/provider/openai"
)

type Config struct {
	Workers        int
	IncludeTests   bool
	AIProvider     string
	OllamaURL      string
	OllamaModel    string
	OllamaNumCtx   int
	OpenAIURL      string
	OpenAIModel    string
	OpenAIKey      string
	GigaChatKey    string
	GigaChatScope  string
	CodeQLMaxFiles int
	AIParallel     int
	MongoURI       string
	FeedbackIn     string
	AIBudget       int
	FailOnSeverity string
	FailOnVerdict  string
	SnippetRadius  int
	Addr           string
}

func LoadConfig() Config {
	return Config{
		Workers:        envInt("SAST_WORKERS", runtime.NumCPU()),
		IncludeTests:   envBool("SAST_INCLUDE_TESTS", false),
		AIProvider:     envString("SAST_AI_PROVIDER", "ollama-agentic"),
		OllamaURL:      envString("SAST_OLLAMA_URL", "http://127.0.0.1:11434"),
		OllamaModel:    envString("SAST_OLLAMA_MODEL", "qwen2.5:3b-instruct"),
		OllamaNumCtx:   envInt("SAST_OLLAMA_NUM_CTX", 4096),
		OpenAIURL:      envString("SAST_OPENAI_URL", "https://api.openai.com/v1"),
		OpenAIModel:    envString("SAST_OPENAI_MODEL", "gpt-4o-mini"),
		OpenAIKey:      envString("SAST_OPENAI_KEY", ""),
		GigaChatKey:    envString("SAST_GIGACHAT_KEY", envString("SAST_OPENAI_KEY", "")),
		GigaChatScope:  envString("SAST_GIGACHAT_SCOPE", "GIGACHAT_API_PERS"),
		CodeQLMaxFiles: envInt("SAST_CODEQL_MAX_FILES", 10000),
		AIParallel:     envInt("SAST_AI_PARALLEL", 1),
		MongoURI:       envString("SAST_MONGO_URI", ""),
		FeedbackIn:     envString("SAST_FEEDBACK_IN", ""),
		AIBudget:       envInt("SAST_AI_BUDGET", 0),
		FailOnSeverity: envString("SAST_FAIL_ON_SEVERITY", "MEDIUM"),
		FailOnVerdict:  envString("SAST_FAIL_ON_VERDICT", "true_positive"),
		SnippetRadius:  envInt("SAST_SNIPPET_RADIUS", 8),
		Addr:           envString("SAST_SERVER_ADDR", ":8080"),
	}
}

func buildProvider(cfg Config) (agent.TriageProvider, error) {
	radius := cfg.SnippetRadius
	switch strings.ToLower(cfg.AIProvider) {
	case "noop":
		return noop.New(), nil
	case "ollama":
		return ollama.New(radius, cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaNumCtx), nil
	case "ollama-agentic":
		return ollama.NewAgentic(radius, cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaNumCtx), nil
	case "openai":
		return openai.New(radius, cfg.OpenAIURL, cfg.OpenAIKey, cfg.OpenAIModel), nil
	case "openai-agentic":
		return openai.NewAgentic(radius, cfg.OpenAIURL, cfg.OpenAIKey, cfg.OpenAIModel), nil
	case "gigachat":
		return gigachat.New(radius, cfg.GigaChatKey, cfg.OpenAIModel, cfg.GigaChatScope), nil
	case "gigachat-agentic":
		return gigachat.NewAgentic(radius, cfg.GigaChatKey, cfg.OpenAIModel, cfg.GigaChatScope), nil
	default:
		return nil, fmt.Errorf("unknown provider %q", cfg.AIProvider)
	}
}

func checkProviderReady(cfg Config) error {
	switch strings.ToLower(cfg.AIProvider) {
	case "ollama", "ollama-agentic":
		return pingOllama(cfg.OllamaURL, cfg.OllamaModel)
	case "openai", "openai-agentic":
		if strings.TrimSpace(cfg.OpenAIKey) == "" {
			return fmt.Errorf("API ключ не задан — укажите его в форме или через переменную окружения SAST_OPENAI_KEY")
		}
		return nil
	case "gigachat", "gigachat-agentic":
		if strings.TrimSpace(cfg.GigaChatKey) == "" {
			return fmt.Errorf("Authorization key не задан — укажите SAST_GIGACHAT_KEY (или legacy SAST_OPENAI_KEY)")
		}
		return nil
	default:
		return nil
	}
}

func pingOllama(baseURL, model string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return fmt.Errorf("cannot reach Ollama at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama at %s returned %s", baseURL, resp.Status)
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil
	}
	modelBase := strings.SplitN(model, ":", 2)[0]
	available := make([]string, 0, len(tags.Models))
	for _, m := range tags.Models {
		available = append(available, m.Name)
		if strings.HasPrefix(m.Name, modelBase) {
			return nil
		}
	}
	if len(available) == 0 {
		return fmt.Errorf("model %q is not pulled in Ollama; run: ollama pull %s", model, model)
	}
	return fmt.Errorf(
		"model %q is not pulled in Ollama; run: ollama pull %s (available: %s)",
		model, model, strings.Join(available, ", "),
	)
}

func applyFormOverrides(cfg *Config, r *http.Request) {
	if v := r.FormValue("provider"); v != "" {
		cfg.AIProvider = v
	}
	if v := r.FormValue("ai_budget"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.AIBudget = n
		}
	}
	if v := r.FormValue("fail_on_severity"); v != "" {
		cfg.FailOnSeverity = v
	}
	if v := r.FormValue("fail_on_verdict"); v != "" {
		cfg.FailOnVerdict = v
	}
	if v := r.FormValue("snippet_radius"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SnippetRadius = n
		}
	}
	if v := r.FormValue("include_tests"); v != "" {
		cfg.IncludeTests = v == "true" || v == "1" || v == "on"
	}
	if v := r.FormValue("openai_key"); strings.TrimSpace(v) != "" {
		cfg.OpenAIKey = v
		if strings.TrimSpace(cfg.GigaChatKey) == "" {
			cfg.GigaChatKey = v
		}
	}
	if v := r.FormValue("gigachat_key"); strings.TrimSpace(v) != "" {
		cfg.GigaChatKey = v
	}
	if v := r.FormValue("openai_model"); strings.TrimSpace(v) != "" {
		cfg.OpenAIModel = v
	}
	if v := r.FormValue("openai_url"); strings.TrimSpace(v) != "" {
		cfg.OpenAIURL = v
	}
	if v := r.FormValue("gigachat_scope"); strings.TrimSpace(v) != "" {
		cfg.GigaChatScope = v
	}
}

func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}
