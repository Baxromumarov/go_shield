// Package app wires GoShield components into one HTTP handler.
//
// This file is the composition root of the project. It connects configuration,
// middleware, and the reverse proxy into the final request pipeline.
//
// Plan: when a new security component is added, build it here and place it in
// the correct order in the middleware chain. main.go should call only app.New.
package app

import (
	"net/http"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/middleware/clientip"
	"github.com/baxromumarov/go_shield/internal/middleware/cors"
	"github.com/baxromumarov/go_shield/internal/middleware/iplist"
	"github.com/baxromumarov/go_shield/internal/middleware/logging"
	"github.com/baxromumarov/go_shield/internal/middleware/ratelimit"
	"github.com/baxromumarov/go_shield/internal/middleware/requestid"
	"github.com/baxromumarov/go_shield/internal/middleware/sizelimit"
	"github.com/baxromumarov/go_shield/internal/proxy"
	"github.com/baxromumarov/go_shield/internal/waf"
)

// New creates the full GoShield HTTP handler.
func New(cfg *config.Config) (http.Handler, error) {
	backendProxy, err := proxy.NewReverseProxy(cfg.Backend.URL)
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
		ratelimit.Middleware(cfg.RateLimits),
		cors.Middleware(cfg.CORS),
		// auth.Middleware(cfg.JWT),
		// scanner.Middleware(cfg.Scanner),
	), nil
}
