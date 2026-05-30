package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsInvalidBackendURL(t *testing.T) {
	cfg := validTestConfig()
	cfg.Backend.URL = "localhost:8081"

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backend.url") {
		t.Fatalf("expected backend URL validation error, got %v", err)
	}
}

func TestValidateRejectsEnabledJWTWithoutSecret(t *testing.T) {
	cfg := validTestConfig()
	cfg.JWT.Enabled = true
	cfg.JWT.Secret = ""

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "jwt.secret") {
		t.Fatalf("expected JWT secret validation error, got %v", err)
	}
}

func TestValidateRejectsWildcardOriginWithCredentials(t *testing.T) {
	cfg := validTestConfig()
	cfg.CORS.AllowCredentials = true
	cfg.CORS.AllowedOrigins = []string{"*"}

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cors.allowed_origins") {
		t.Fatalf("expected CORS validation error, got %v", err)
	}
}

func TestValidateRejectsInvalidRateLimitKeyMode(t *testing.T) {
	cfg := validTestConfig()
	cfg.RateLimits.KeyBy = "session"

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rate_limits.key_by") {
		t.Fatalf("expected rate limit key validation error, got %v", err)
	}
}

func TestLoadConfigAppliesDefaultsAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte(`
server:
  listen_addr: ":8080"
backend:
  url: "http://localhost:8081"
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}

	if cfg.State.Backend != "memory" {
		t.Fatalf("expected default state backend %q, got %q", "memory", cfg.State.Backend)
	}

	if cfg.Backend.ResponseHeaderTimeoutSeconds != 10 {
		t.Fatalf("expected default backend response timeout %d, got %d", 10, cfg.Backend.ResponseHeaderTimeoutSeconds)
	}
}

func validTestConfig() Config {
	cfg := defaultConfig()
	cfg.JWT.Secret = "test-secret"
	cfg.CORS.AllowCredentials = false
	cfg.CORS.AllowedOrigins = nil
	return cfg
}
