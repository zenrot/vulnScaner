package main

import (
	"net/http"
	"os"
	"time"

	"vulnscanner/internal/api"
	"vulnscanner/internal/logging"
)

func main() {
	cfg := api.LoadConfig()
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.New(cfg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      30 * time.Minute,
	}
	logging.L().Info("sast-server listening", "addr", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.L().Error("server failed", "err", err)
		os.Exit(2)
	}
}
