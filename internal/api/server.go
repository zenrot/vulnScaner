package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vulnscanner/internal/agent"
	"vulnscanner/internal/history"
	"vulnscanner/internal/jobs"
	"vulnscanner/internal/logging"
	"vulnscanner/internal/scanner"
)

type Server struct {
	cfg       Config
	mux       *http.ServeMux
	histStore *history.Store
	jobMgr    *jobs.Manager
}

type scanResponse struct {
	ShouldFail    bool         `json:"should_fail"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	Report        agent.Report `json:"report"`
}

type sseWriter struct {
	w  http.ResponseWriter
	fl http.Flusher
}

func (s *sseWriter) send(v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(s.w, "data: %s\n\n", b)
	s.fl.Flush()
}

func New(cfg Config) *Server {
	histStore, err := history.New(cfg.MongoURI)
	if err != nil {
		logging.L().Warn("history store disabled", "err", err)
	}
	srv := &Server{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		histStore: histStore,
		jobMgr:    jobs.NewManager(),
	}
	srv.mux.HandleFunc("/healthz", srv.handleHealthz)
	srv.mux.HandleFunc("/history", srv.handleHistoryList)
	srv.mux.HandleFunc("/history/", srv.handleHistoryGet)
	srv.mux.HandleFunc("/scan", srv.handleScan)
	srv.mux.HandleFunc("/provider/test", srv.handleProviderTest)
	srv.mux.HandleFunc("/scan/stream", srv.handleScanStream)
	srv.mux.HandleFunc("/jobs/", srv.handleJobStream)
	return srv
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.mux.ServeHTTP(w, r)
}

func (srv *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (srv *Server) handleHistoryList(w http.ResponseWriter, _ *http.Request) {
	if srv.histStore == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]struct{}{})
		return
	}
	summaries, err := srv.histStore.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if summaries == nil {
		summaries = []history.Summary{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summaries)
}

func (srv *Server) handleHistoryGet(w http.ResponseWriter, r *http.Request) {
	if srv.histStore == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/history/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	rec, err := srv.histStore.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rec == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

func (srv *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	tmpDir, localCfg, cleanup, ok := parseUpload(r, w, srv.cfg)
	if !ok {
		return
	}
	defer cleanup()
	logging.L().Info("scan request accepted",
		"mode", "sync",
		"provider", localCfg.AIProvider,
		"ai_budget", localCfg.AIBudget,
		"fail_on_severity", localCfg.FailOnSeverity,
		"fail_on_verdict", localCfg.FailOnVerdict,
	)

	if err := checkProviderReady(localCfg); err != nil {
		http.Error(w, fmt.Sprintf("Проверка провайдера не прошла: %v", err), http.StatusServiceUnavailable)
		return
	}

	rep, shouldFail, err := runScan(r.Context(), localCfg, findGoRoot(tmpDir), nil)
	if err != nil {
		logging.L().Error("scan failed", "mode", "sync", "provider", localCfg.AIProvider, "err", err)
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}
	logging.L().Info("scan completed",
		"mode", "sync",
		"provider", localCfg.AIProvider,
		"should_fail", shouldFail,
		"findings_total", rep.Stats.TotalFindings,
		"findings_ai_triaged", rep.Stats.AITriagedFindings,
		"findings_fallback", rep.Stats.FallbackFindings,
	)
	resp := scanResponse{ShouldFail: shouldFail, CorrelationID: r.FormValue("correlation_id"), Report: rep}
	if srv.histStore != nil {
		archName := ""
		if r.MultipartForm != nil {
			if fhs := r.MultipartForm.File["archive"]; len(fhs) > 0 {
				archName = fhs[0].Filename
			}
		}
		_, _ = srv.histStore.Save(archName, localCfg.AIProvider, shouldFail, rep.Stats, resp)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (srv *Server) handleProviderTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	localCfg := srv.cfg
	applyFormOverrides(&localCfg, r)

	writeResult := func(ok bool, msg string, latencyMs int64) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         ok,
			"message":    msg,
			"latency_ms": latencyMs,
		})
	}

	if err := checkProviderReady(localCfg); err != nil {
		logging.L().Warn("provider readiness check failed", "provider", localCfg.AIProvider, "err", err)
		writeResult(false, err.Error(), 0)
		return
	}

	provider, err := buildProvider(localCfg)
	if err != nil {
		writeResult(false, err.Error(), 0)
		return
	}

	testFinding := scanner.Finding{
		RuleID: "TEST", Title: "connection test",
		Severity: scanner.SeverityLow,
		Evidence: "test", WhyItMatters: "test", Remediation: "none",
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	start := time.Now()
	_, err = provider.Triage(ctx, testFinding)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		logging.L().Warn("provider test failed", "provider", provider.Name(), "latency_ms", elapsed, "err", err)
		writeResult(false, err.Error(), elapsed)
	} else {
		logging.L().Info("provider test ok", "provider", provider.Name(), "latency_ms", elapsed)
		writeResult(true, fmt.Sprintf("Провайдер %s отвечает", provider.Name()), elapsed)
	}
}

func (srv *Server) handleScanStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	tmpDir, localCfg, cleanup, ok := parseUpload(r, w, srv.cfg)
	if !ok {
		return
	}
	logging.L().Info("scan request accepted",
		"mode", "stream",
		"provider", localCfg.AIProvider,
		"ai_budget", localCfg.AIBudget,
		"fail_on_severity", localCfg.FailOnSeverity,
		"fail_on_verdict", localCfg.FailOnVerdict,
	)

	fl, fok := w.(http.Flusher)
	if !fok {
		cleanup()
		http.Error(w, "streaming not supported by this server", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	sse := &sseWriter{w: w, fl: fl}

	if err := checkProviderReady(localCfg); err != nil {
		cleanup()
		sse.send(map[string]any{"type": "error", "message": fmt.Sprintf("Проверка провайдера не прошла: %v", err)})
		return
	}

	archName := ""
	if r.MultipartForm != nil {
		if fhs := r.MultipartForm.File["archive"]; len(fhs) > 0 {
			archName = fhs[0].Filename
		}
	}
	corrID := r.FormValue("correlation_id")

	job := srv.jobMgr.Create(corrID + "_" + fmt.Sprintf("%d", time.Now().UnixNano()))
	logging.L().Info("scan stream job created", "job_id", job.ID, "provider", localCfg.AIProvider)
	sse.send(map[string]any{"type": "job_id", "id": job.ID})

	go func() {
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		job.Publish(map[string]any{"type": "scanning"})

		rep, shouldFail, scanErr := runScan(ctx, localCfg, findGoRoot(tmpDir), job.Publish)
		if scanErr != nil {
			logging.L().Error("scan failed", "mode", "stream", "job_id", job.ID, "provider", localCfg.AIProvider, "err", scanErr)
			job.Publish(map[string]any{"type": "error", "message": scanErr.Error()})
			return
		}
		logging.L().Info("scan completed",
			"mode", "stream",
			"job_id", job.ID,
			"provider", localCfg.AIProvider,
			"should_fail", shouldFail,
			"findings_total", rep.Stats.TotalFindings,
			"findings_ai_triaged", rep.Stats.AITriagedFindings,
			"findings_fallback", rep.Stats.FallbackFindings,
		)
		resp := scanResponse{ShouldFail: shouldFail, CorrelationID: corrID, Report: rep}
		if srv.histStore != nil {
			_, _ = srv.histStore.Save(archName, localCfg.AIProvider, shouldFail, rep.Stats, resp)
		}
		job.Publish(map[string]any{"type": "done", "result": resp})
	}()

	sub, unsub := job.Subscribe()
	defer unsub()
	for {
		select {
		case ev, more := <-sub:
			if !more {
				return
			}
			sse.send(ev)
			t, _ := ev["type"].(string)
			if t == "done" || t == "error" {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func (srv *Server) handleJobStream(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/stream")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	job := srv.jobMgr.Get(id)
	if job == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	sse := &sseWriter{w: w, fl: fl}

	sub, unsub := job.Subscribe()
	defer unsub()
	for {
		select {
		case ev, more := <-sub:
			if !more {
				return
			}
			sse.send(ev)
			t, _ := ev["type"].(string)
			if t == "done" || t == "error" {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
