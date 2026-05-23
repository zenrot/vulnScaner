package logging

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	once   sync.Once
	logger *slog.Logger
)

func L() *slog.Logger {
	once.Do(func() {
		level := slog.LevelInfo
		switch strings.ToLower(strings.TrimSpace(os.Getenv("SAST_LOG_LEVEL"))) {
		case "debug":
			level = slog.LevelDebug
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}

		opts := &slog.HandlerOptions{Level: level}
		if strings.EqualFold(strings.TrimSpace(os.Getenv("SAST_LOG_JSON")), "true") {
			logger = slog.New(slog.NewJSONHandler(os.Stdout, opts))
		} else {
			logger = slog.New(slog.NewTextHandler(os.Stdout, opts))
		}
		slog.SetDefault(logger)
	})
	return logger
}
