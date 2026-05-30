// Project is for learning purpose.
// For production, some parts need changes.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/baxromumarov/go_shield/internal/app"
	"github.com/baxromumarov/go_shield/internal/config"
)

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	handler, err := app.New(cfg)
	if err != nil {
		slog.Error("failed to build application", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("GoShield listening", "addr", cfg.Server.ListenAddr, "backend", cfg.Backend.URL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http listen error", "error", err)
			os.Exit(1)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	slog.Info("GoShield is shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("http shutdown error", "error", err)
		os.Exit(1)
	}
}
