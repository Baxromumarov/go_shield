package cors

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.CORSConfig) waf.Middleware {
	policy := newPolicy(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			if !policy.hostAllowed(r.Host) {
				http.Error(w, "invalid host", http.StatusBadRequest)
				return
			}

			if !policy.methodAllowed(r.Method) {
				w.Header().Set("Allow", policy.allowedMethodsValue)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			origin := r.Header.Get("Origin")
			if origin != "" {
				if !policy.originAllowed(origin) {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}

				policy.setCORSHeaders(w, origin)
			}

			if isPreflight(r) {
				if !policy.preflightAllowed(r) {
					http.Error(w, "forbidden preflight", http.StatusForbidden)
					return
				}

				policy.setPreflightHeaders(w)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// i used bool for value to make life easier
// but bool takes 1 byte in golang struct 0
// for production it is usually considered better approach
// to use struct{}. Because tired of using comma-ok pattern
type policy struct {
	allowedHosts        map[string]bool
	allowedOrigins      map[string]bool
	allowedMethods      map[string]bool
	allowedHeaders      map[string]bool
	allowedMethodsValue string
	allowedHeadersValue string
	allowCredentials    bool
	maxAgeSeconds       int
}

func newPolicy(cfg config.CORSConfig) policy {
	return policy{
		allowedHosts:        stringSet(cfg.AllowedHosts, normalizeHost),
		allowedOrigins:      stringSet(cfg.AllowedOrigins, normalizeOrigin),
		allowedMethods:      stringSet(cfg.AllowedMethods, normalizeMethod),
		allowedHeaders:      stringSet(cfg.AllowedHeaders, normalizeHeader),
		allowedMethodsValue: strings.Join(cfg.AllowedMethods, ", "),
		allowedHeadersValue: strings.Join(cfg.AllowedHeaders, ", "),
		allowCredentials:    cfg.AllowCredentials,
		maxAgeSeconds:       cfg.MaxAgeSeconds,
	}
}

func (p policy) hostAllowed(host string) bool {
	if len(p.allowedHosts) == 0 {
		return true
	}

	return p.allowedHosts[normalizeHost(host)]
}

func (p policy) originAllowed(origin string) bool {
	origin = normalizeOrigin(origin)
	if origin == "" {
		return false
	}

	if p.allowedOrigins[origin] {
		return true
	}

	if p.allowedOrigins["*"] && !p.allowCredentials {
		return true
	}

	return false
}

func (p policy) methodAllowed(method string) bool {
	if len(p.allowedMethods) == 0 {
		return true
	}

	return p.allowedMethods[normalizeMethod(method)]
}

func (p policy) headersAllowed(headerValue string) bool {
	if strings.TrimSpace(headerValue) == "" {
		return true
	}

	for header := range strings.SplitSeq(headerValue, ",") {
		if !p.allowedHeaders[normalizeHeader(header)] {
			return false
		}
	}

	return true
}

func (p policy) preflightAllowed(r *http.Request) bool {
	if r.Header.Get("Origin") == "" {
		return false
	}

	requestMethod := r.Header.Get("Access-Control-Request-Method")
	if !p.methodAllowed(requestMethod) {
		return false
	}

	return p.headersAllowed(r.Header.Get("Access-Control-Request-Headers"))
}

func (p policy) setCORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Add("Vary", "Origin")

	if p.allowedOrigins["*"] && !p.allowCredentials {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if p.allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

func (p policy) setPreflightHeaders(w http.ResponseWriter) {
	if p.allowedMethodsValue != "" {
		w.Header().Set("Access-Control-Allow-Methods", p.allowedMethodsValue)
	}

	if p.allowedHeadersValue != "" {
		w.Header().Set("Access-Control-Allow-Headers", p.allowedHeadersValue)
	}

	if p.maxAgeSeconds > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(p.maxAgeSeconds))
	}

	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
}

func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

func stringSet(values []string, normalize func(string) string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		value = normalize(value)
		if value == "" {
			continue
		}

		set[value] = true
	}

	return set
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func normalizeOrigin(origin string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(origin)), "/")
}

func normalizeMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}

func normalizeHeader(header string) string {
	return strings.ToLower(strings.TrimSpace(header))
}
