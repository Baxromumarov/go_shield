package internal

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	RequestLimits RequestLimits `yaml:"request_limits"`
}

type RequestLimits struct {
	DefaultMaxBodyBytes int            `yaml:"default_max_body_bytes"`
	Methods             map[string]int `yaml:"methods"`
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
