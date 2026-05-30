// Package app builds the GoShield HTTP handler stack.
package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/middleware/auth"
	"github.com/baxromumarov/go_shield/internal/middleware/clientip"
	"github.com/baxromumarov/go_shield/internal/middleware/cors"
	"github.com/baxromumarov/go_shield/internal/middleware/iplist"
	"github.com/baxromumarov/go_shield/internal/middleware/logging"
	"github.com/baxromumarov/go_shield/internal/middleware/ratelimit"
	"github.com/baxromumarov/go_shield/internal/middleware/requestid"
	"github.com/baxromumarov/go_shield/internal/middleware/scanner"
	"github.com/baxromumarov/go_shield/internal/middleware/sizelimit"
	"github.com/baxromumarov/go_shield/internal/proxy"
	"github.com/baxromumarov/go_shield/internal/state"
	"github.com/baxromumarov/go_shield/internal/waf"
)

// New creates the full GoShield HTTP handler.
func New(cfg *config.Config) (http.Handler, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	stateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stateStore, err := state.New(stateCtx, cfg.State)
	if err != nil {
		return nil, err
	}

	backendProxy, err := proxy.NewReverseProxy(cfg.Backend)
	if err != nil {
		return nil, err
	}

	return waf.Chain(
		backendProxy,
		requestid.Middleware(),
		logging.Middleware(cfg.Logging),
		clientip.Middleware(cfg.TrustedProxies),
		sizelimit.Middleware(cfg.RequestLimits),
		iplist.Middleware(cfg.BannedIPs),
		cors.Middleware(cfg.CORS),
		auth.Middleware(cfg.JWT),
		ratelimit.Middleware(cfg.RateLimits, stateStore),
		scanner.Middleware(cfg.Scanner, stateStore),
	), nil
}
