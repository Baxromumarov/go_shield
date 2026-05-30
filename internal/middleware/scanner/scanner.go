package scanner

import (
	"bytes"
	"errors"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/state"
	"github.com/baxromumarov/go_shield/internal/waf"
)

const maxDecodePasses = 2
const defaultRuntimeBlockTTL = 15 * time.Minute

// Common SQLi and XSS patterns. Regex WAF: brave, cheap, and not magic.
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

func Middleware(cfg config.ScannerConfig, stores ...state.BlocklistStore) waf.Middleware {
	blocklist := newBlocklist(cfg, stores...)

	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		if blocked, err := blocklist.contains(r); err != nil {
			slog.Warn("scanner blocklist lookup failed", "error", err)
		} else if blocked {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if cfg.ScanQuery && malicious(r.URL.RawQuery) {
			block(w, r, blocklist)
			return
		}

		if cfg.ScanHeaders && headersMalicious(r.Header) {
			block(w, r, blocklist)
			return
		}

		if cfg.ScanBody && r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				var maxBytesError *http.MaxBytesError
				if errors.As(err, &maxBytesError) {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}

				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}

			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if malicious(string(bodyBytes)) {
				block(w, r, blocklist)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// If someone tries to attack our backend,
// put that bastard into timeout.
// TTL matters because false positives and
// shared NAT IPs are real life.
type runtimeBlocklist struct {
	store state.BlocklistStore
	ttl   time.Duration
}

func newBlocklist(cfg config.ScannerConfig, stores ...state.BlocklistStore) *runtimeBlocklist {
	store := state.BlocklistStore(state.NewMemory())
	if len(stores) > 0 && stores[0] != nil {
		store = stores[0]
	}

	ttl := time.Duration(cfg.RuntimeBlockTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultRuntimeBlockTTL
	}

	return &runtimeBlocklist{
		store: store,
		ttl:   ttl,
	}
}

func (b *runtimeBlocklist) add(r *http.Request) error {
	ip := requestIP(r)
	if ip == "" {
		return nil
	}

	return b.store.Block(r.Context(), state.BlockEntry{
		Key: scannerBlockKey(ip),
		TTL: b.ttl,
	})
}

func (b *runtimeBlocklist) contains(r *http.Request) (bool, error) {
	ip := requestIP(r)
	if ip == "" {
		return false, nil
	}

	return b.store.Blocked(r.Context(), scannerBlockKey(ip))
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
	if err := blockedIPs.add(r); err != nil {
		slog.Warn("scanner blocklist update failed", "error", err)
	}

	http.Error(w, "forbidden payload", http.StatusForbidden)
}

func requestIP(r *http.Request) string {
	if clientIP, ok := waf.LookupCtxKey(r, waf.ClientIPKey); ok && clientIP != "" {
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

func scannerBlockKey(ip string) string {
	return "scanner:ip:" + ip
}
