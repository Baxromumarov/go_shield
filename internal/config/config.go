package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	RequestLimits   RequestLimits   `yaml:"request_limits"`
	RateLimitConfig RateLimitConfig `yaml:"rate_limits"`
	JWT             JWTConfig       `yaml:"jwt"`
}

type JWTConfig struct {
	Secret string `yaml:"secret"`
}

type RequestLimits struct {
	DefaultMaxBodyBytes int                          `yaml:"default_max_body_bytes"`
	Methods             map[string]int               `yaml:"methods"`
	Routes              map[string]RequestLimitRoute `yaml:"routes"`
}

type RequestLimitRoute struct {
	MaxBodyBytes int `yaml:"max_body_bytes"`
}

type RateLimitConfig struct {
	Enabled bool                       `yaml:"enabled"`
	Default TokenBucketRule            `yaml:"default"`
	Routes  map[string]TokenBucketRule `yaml:"routes"`
}

type TokenBucketRule struct {
	Capacity            int64   `yaml:"capacity"`
	RefillRatePerSecond float64 `yaml:"refill_rate_per_second"`
	Key                 string  `yaml:"key"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
