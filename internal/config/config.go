// Package config contains GoShield configuration models and YAML loading.
//
// This file is for translating config.yaml into strongly typed Go structs.
// Every major GoShield component should receive its settings from this package
// instead of hardcoding values.
//
// Plan: add validation here as the project grows, for example checking that
// backend.url is valid, JWT secrets are present when JWT is enabled, and route
// limits are not negative.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config is the root configuration for the whole GoShield process.
type Config struct {
	Server         ServerConfig      `yaml:"server"`
	Backend        BackendConfig     `yaml:"backend"`
	RequestLimits  RequestLimits     `yaml:"request_limits"`
	RateLimits     RateLimitConfig   `yaml:"rate_limits"`
	JWT            JWTConfig         `yaml:"jwt"`
	BannedIPs      []string          `yaml:"banned_ips"`
	Scanner        ScannerConfig     `yaml:"scanner"`
	CORS           CORSConfig        `yaml:"cors"`
	Logging        SecurityLogConfig `yaml:"logging"`
	TrustedProxies []string          `yaml:"trusted_proxies"`
}

// ServerConfig controls the public GoShield HTTP server.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// BackendConfig controls the upstream API that GoShield proxies to.
type BackendConfig struct {
	URL string `yaml:"url"`
}

// RequestLimits controls maximum request body sizes by method and route.
type RequestLimits struct {
	DefaultMaxBodyBytes int                          `yaml:"default_max_body_bytes"`
	Methods             map[string]int               `yaml:"methods"`
	Routes              map[string]RequestLimitRoute `yaml:"routes"`
}

// RequestLimitRoute is a per-route request body limit override.
type RequestLimitRoute struct {
	MaxBodyBytes int `yaml:"max_body_bytes"`
}

// RateLimitConfig controls token bucket rate limiting.
type RateLimitConfig struct {
	Enabled bool                       `yaml:"enabled"`
	Routes  map[string]TokenBucketRule `yaml:"routes"`
}

// TokenBucketRule describes one token bucket policy.
type TokenBucketRule struct {
	Capacity            int64   `yaml:"capacity"`
	RefillRatePerSecond float64 `yaml:"refill_rate_per_second"`
}

// JWTConfig controls JWT authentication and route protection.
type JWTConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Secret          string   `yaml:"secret"`
	ProtectedRoutes []string `yaml:"protected_routes"`
	SkipRoutes      []string `yaml:"skip_routes"`
}

// ScannerConfig controls SQLi/XSS/payload scanning.
type ScannerConfig struct {
	Enabled     bool `yaml:"enabled"`
	ScanQuery   bool `yaml:"scan_query"`
	ScanHeaders bool `yaml:"scan_headers"`
	ScanBody    bool `yaml:"scan_body"`
}

// CORSConfig controls origin/method/header policy checks.
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedHosts     []string `yaml:"allowed_hosts"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAgeSeconds    int      `yaml:"max_age_seconds"`
}

// SecurityLogConfig controls security audit logging.
type SecurityLogConfig struct {
	Enabled bool `yaml:"enabled"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// NOTE: for testing only
func defaultConfig() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr: ":8080",
		},
		Backend: BackendConfig{
			URL: "http://localhost:8081",
		},
		RequestLimits: RequestLimits{
			DefaultMaxBodyBytes: 1 << 20, // 1048576
		},
		Logging: SecurityLogConfig{
			Enabled: true,
		},
	}
}
