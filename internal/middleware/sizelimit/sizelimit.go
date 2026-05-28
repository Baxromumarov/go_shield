package sizelimit

import (
	"net/http"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.RequestLimits) waf.Middleware {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := int64(limitForRequest(r, cfg))

			if limit <= 0 { // just guard checking
				next.ServeHTTP(w, r)
				return
			}

			if r.ContentLength > limit {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, limit)

			next.ServeHTTP(w, r)
		})
	}
}

func limitForRequest(r *http.Request, cfg config.RequestLimits) int {
	limit := cfg.DefaultMaxBodyBytes

	if cfg.Methods != nil {
		if methodLimit, ok := cfg.Methods[r.Method]; ok {
			limit = methodLimit
		}
	}

	if cfg.Routes != nil {
		if routeLimit, ok := cfg.Routes[r.URL.Path]; ok {
			limit = routeLimit.MaxBodyBytes
		}
	}

	return limit
}
