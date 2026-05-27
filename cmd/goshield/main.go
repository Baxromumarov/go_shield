// Package main is the executable entry point for GoShield.
//
// This file is responsible only for application startup:
//   - load configuration from config.yaml
//   - build the GoShield HTTP handler from internal/app
//   - start the HTTP server
//   - handle graceful shutdown signals
//
// Plan: keep this file small. All WAF, proxy, auth, rate-limit, scanner,
// and logging logic should live in internal packages, not in main.go.
package main

import (
	"context"
	"log"
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
		log.Fatalf("failed to load config: %v", err)
	}

	handler, err := app.New(cfg)
	if err != nil {
		log.Fatalf("failed to build application: %v", err)
	}

	server := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("GoShield listening on %s and proxying to %s", cfg.Server.ListenAddr, cfg.Backend.URL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http listen error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("GoShield is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("http shutdown error: %v", err)
	}
}
