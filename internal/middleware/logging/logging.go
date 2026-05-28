package logging

import (
	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.SecurityLogConfig) waf.Middleware {
	return nil
}
