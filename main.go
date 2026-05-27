package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/baxromumarov/go_shield/internal/config"
)

const (
	addr = ":8080"
)

type server struct{}

func main() {
	server := &http.Server{
		Addr: addr,
	}

	config, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	_ = config

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Server is shutting down...")

		if err := server.Close(); err != nil {
			log.Fatalf("HTTP close error: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP listen error: %v", err)
	}
}
