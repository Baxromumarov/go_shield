package sizelimit

import (
	"net/http"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.RequestLimits) waf.Middleware {
	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		limit := int64(limitForRequest(r, cfg))

		if limit < 0 {
			next.ServeHTTP(w, r)
			return
		}

		if limit == 0 && hasRequestBody(r) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
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

func hasRequestBody(r *http.Request) bool {
	return r.ContentLength != 0
}
