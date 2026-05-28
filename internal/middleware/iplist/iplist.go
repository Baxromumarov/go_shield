package iplist

import (
	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.IPListsConfig) waf.Middleware { return nil }
