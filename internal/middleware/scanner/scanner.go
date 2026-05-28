package scanner

import (
	"bytes"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

const maxDecodePasses = 2

// common SQLi and XSS list
var attackPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|[^\w])(?:or|and)\s+['"]?[\w.-]+['"]?\s*=\s*['"]?[\w.-]+`),
	regexp.MustCompile(`(?i)\bunion\s+(?:all\s+)?select\b`),
	regexp.MustCompile(`(?i)\b(?:select|insert|update|delete|drop|alter|create|truncate)\b.+\b(?:from|into|table|database|where|set)\b`),
	regexp.MustCompile(`(?i)\b(?:sleep|benchmark)\s*\(`),
	regexp.MustCompile(`(?i)\binformation_schema\b`),
	regexp.MustCompile(`(?i)(?:--|#|/\*)\s*$`),
	regexp.MustCompile(`(?i)<\s*/?\s*script\b`),
	regexp.MustCompile(`(?i)<\s*(?:iframe|object|embed|svg|img|body)\b[^>]*(?:on\w+\s*=|src\s*=|href\s*=)`),
	regexp.MustCompile(`(?i)\bon\w+\s*=`),
	regexp.MustCompile(`(?i)\b(?:javascript|data)\s*:`),
}

func Middleware(cfg config.ScannerConfig) waf.Middleware {
	blockedIPs := newRuntimeBlocklist()

	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		if blockedIPs.contains(requestIP(r)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if cfg.ScanQuery && malicious(r.URL.RawQuery) {
			block(w, r, blockedIPs)
			return
		}

		if cfg.ScanHeaders && headersMalicious(r.Header) {
			block(w, r, blockedIPs)
			return
		}

		if cfg.ScanBody && r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}

			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if malicious(string(bodyBytes)) {
				block(w, r, blockedIPs)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Runtime blocks stop repeated scanner hits from the same client IP.
type runtimeBlocklist struct {
	mu  sync.RWMutex
	ips map[string]bool
}

func newRuntimeBlocklist() *runtimeBlocklist {
	return &runtimeBlocklist{
		ips: make(map[string]bool),
	}
}

func (b *runtimeBlocklist) add(ip string) {
	if ip == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.ips[ip] = true
}

func (b *runtimeBlocklist) contains(ip string) bool {
	if ip == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.ips[ip]
}

func headersMalicious(header http.Header) bool {
	for name, values := range header {
		if strings.EqualFold(name, "Authorization") {
			continue
		}

		if malicious(name) {
			return true
		}

		if slices.ContainsFunc(values, malicious) {
			return true
		}
	}

	return false
}

func malicious(value string) bool {
	value = normalize(value)
	if value == "" {
		return false
	}

	for _, pattern := range attackPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	return false
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	for range maxDecodePasses {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}

		value = decoded
	}

	value = html.UnescapeString(value)
	return strings.ToLower(value)
}

func block(w http.ResponseWriter, r *http.Request, blockedIPs *runtimeBlocklist) {
	blockedIPs.add(requestIP(r))
	http.Error(w, "forbidden payload", http.StatusForbidden)
}

func requestIP(r *http.Request) string {
	if clientIP := waf.GetCtxKey(r, waf.ClientIPKey); clientIP != "" {
		return clientIP
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	return ip.String()
}
