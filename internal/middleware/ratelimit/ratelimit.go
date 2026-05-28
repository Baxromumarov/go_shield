package ratelimit

import (
	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.RateLimitConfig) waf.Middleware { return nil }
