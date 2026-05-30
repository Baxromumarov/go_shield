// Package config loads and validates GoShield configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

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
	State          StateConfig       `yaml:"state"`
}

// ServerConfig controls the public GoShield HTTP server.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// BackendConfig controls the upstream API that GoShield proxies to.
type BackendConfig struct {
	URL                          string `yaml:"url"`
	DialTimeoutSeconds           int    `yaml:"dial_timeout_seconds"`
	ResponseHeaderTimeoutSeconds int    `yaml:"response_header_timeout_seconds"`
	IdleConnTimeoutSeconds       int    `yaml:"idle_conn_timeout_seconds"`
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
	Enabled  bool                       `yaml:"enabled"`
	KeyBy    string                     `yaml:"key_by"`
	FailOpen bool                       `yaml:"fail_open"`
	Routes   map[string]TokenBucketRule `yaml:"routes"`
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
	Issuer          string   `yaml:"issuer"`
	Audience        string   `yaml:"audience"`
	ProtectedRoutes []string `yaml:"protected_routes"`
	SkipRoutes      []string `yaml:"skip_routes"`
}

// ScannerConfig controls SQLi/XSS/payload scanning.
type ScannerConfig struct {
	Enabled                bool `yaml:"enabled"`
	ScanQuery              bool `yaml:"scan_query"`
	ScanHeaders            bool `yaml:"scan_headers"`
	ScanBody               bool `yaml:"scan_body"`
	RuntimeBlockTTLSeconds int  `yaml:"runtime_block_ttl_seconds"`
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

// StateConfig controls shared WAF state. The memory backend is useful for
// local development; Redis is intended for multi-process or multi-node setups.
type StateConfig struct {
	Backend   string      `yaml:"backend"`
	Namespace string      `yaml:"namespace"`
	Redis     RedisConfig `yaml:"redis"`
}

// RedisConfig controls the Redis client used for distributed WAF state.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks configuration values that would otherwise fail at runtime.
func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.Server.ListenAddr) == "" {
		return fmt.Errorf("server.listen_addr is required")
	}

	if err := validateBackend(cfg.Backend); err != nil {
		return err
	}

	if err := validateRequestLimits(cfg.RequestLimits); err != nil {
		return err
	}

	if err := validateRateLimits(cfg.RateLimits); err != nil {
		return err
	}

	if cfg.JWT.Enabled && strings.TrimSpace(cfg.JWT.Secret) == "" {
		return fmt.Errorf("jwt.secret is required when jwt.enabled is true")
	}

	if cfg.Scanner.RuntimeBlockTTLSeconds < 0 {
		return fmt.Errorf("scanner.runtime_block_ttl_seconds must be >= 0")
	}

	if cfg.CORS.AllowCredentials && containsString(cfg.CORS.AllowedOrigins, "*") {
		return fmt.Errorf("cors.allowed_origins cannot contain * when cors.allow_credentials is true")
	}

	if err := validateState(cfg.State); err != nil {
		return err
	}

	return nil
}

func validateBackend(cfg BackendConfig) error {
	rawURL := strings.TrimSpace(cfg.URL)
	if rawURL == "" {
		return fmt.Errorf("backend.url is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("backend.url is invalid: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("backend.url must include scheme and host")
	}

	if cfg.DialTimeoutSeconds < 0 {
		return fmt.Errorf("backend.dial_timeout_seconds must be >= 0")
	}
	if cfg.ResponseHeaderTimeoutSeconds < 0 {
		return fmt.Errorf("backend.response_header_timeout_seconds must be >= 0")
	}
	if cfg.IdleConnTimeoutSeconds < 0 {
		return fmt.Errorf("backend.idle_conn_timeout_seconds must be >= 0")
	}

	return nil
}

func validateRequestLimits(cfg RequestLimits) error {
	if cfg.DefaultMaxBodyBytes < -1 {
		return fmt.Errorf("request_limits.default_max_body_bytes must be >= -1")
	}

	for method, limit := range cfg.Methods {
		if strings.TrimSpace(method) == "" {
			return fmt.Errorf("request_limits.methods contains an empty method")
		}
		if limit < -1 {
			return fmt.Errorf("request_limits.methods.%s must be >= -1", method)
		}
	}

	for route, limit := range cfg.Routes {
		if strings.TrimSpace(route) == "" {
			return fmt.Errorf("request_limits.routes contains an empty route")
		}
		if limit.MaxBodyBytes < -1 {
			return fmt.Errorf("request_limits.routes.%s.max_body_bytes must be >= -1", route)
		}
	}

	return nil
}

func validateRateLimits(cfg RateLimitConfig) error {
	switch normalizeKeyBy(cfg.KeyBy) {
	case "", "client_ip", "user_id", "user_or_ip", "global":
	default:
		return fmt.Errorf("rate_limits.key_by must be one of client_ip, user_id, user_or_ip, global")
	}

	for route, rule := range cfg.Routes {
		if strings.TrimSpace(route) == "" {
			return fmt.Errorf("rate_limits.routes contains an empty route")
		}
		if rule.Capacity < 0 {
			return fmt.Errorf("rate_limits.routes.%s.capacity must be >= 0", route)
		}
		if rule.RefillRatePerSecond < 0 {
			return fmt.Errorf("rate_limits.routes.%s.refill_rate_per_second must be >= 0", route)
		}
	}

	return nil
}

func validateState(cfg StateConfig) error {
	backend := normalizeStateBackend(cfg.Backend)
	switch backend {
	case "", "memory":
		return nil
	case "redis":
		if strings.TrimSpace(cfg.Redis.Addr) == "" {
			return fmt.Errorf("state.redis.addr is required when state.backend is redis")
		}
		if cfg.Redis.DB < 0 {
			return fmt.Errorf("state.redis.db must be >= 0")
		}
		return nil
	default:
		return fmt.Errorf("state.backend must be memory or redis")
	}
}

func normalizeKeyBy(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeStateBackend(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func defaultConfig() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr: ":8080",
		},
		Backend: BackendConfig{
			URL:                          "http://localhost:8081",
			DialTimeoutSeconds:           5,
			ResponseHeaderTimeoutSeconds: 10,
			IdleConnTimeoutSeconds:       90,
		},
		RequestLimits: RequestLimits{
			DefaultMaxBodyBytes: 1 << 20, // 1048576
		},
		RateLimits: RateLimitConfig{
			KeyBy: "client_ip",
		},
		Scanner: ScannerConfig{
			RuntimeBlockTTLSeconds: 900,
		},
		Logging: SecurityLogConfig{
			Enabled: true,
		},
		State: StateConfig{
			Backend:   "memory",
			Namespace: "goshield",
			Redis: RedisConfig{
				Addr: "localhost:6379",
			},
		},
	}
}
