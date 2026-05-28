package clientip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareAddsClientIPToContext(t *testing.T) {
	var contextClientIP string

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextClientIP = waf.GetCtxKey(r, waf.ClientIPKey)
	})
	handler := Middleware([]string{"10.0.0.10"})(next)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.25")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if contextClientIP != "203.0.113.25" {
		t.Fatalf("expected client IP %q in context, got %q", "203.0.113.25", contextClientIP)
	}
}

func TestResolveClientIPIgnoresForwardedHeadersFromUntrustedRemote(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.25")
	request.Header.Set("X-Real-IP", "203.0.113.26")

	got := resolveClientIP(request, parseTrustedProxies([]string{"10.0.0.10"}))

	if got != "198.51.100.10" {
		t.Fatalf("expected untrusted remote IP %q, got %q", "198.51.100.10", got)
	}
}

func TestResolveClientIPUsesFirstForwardedForIPFromTrustedProxy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.25, 10.0.0.20")

	got := resolveClientIP(request, parseTrustedProxies([]string{"10.0.0.10"}))

	if got != "203.0.113.25" {
		t.Fatalf("expected first forwarded IP %q, got %q", "203.0.113.25", got)
	}
}

func TestResolveClientIPUsesRealIPWhenForwardedForIsMissing(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("X-Real-IP", "203.0.113.26")

	got := resolveClientIP(request, parseTrustedProxies([]string{"10.0.0.10"}))

	if got != "203.0.113.26" {
		t.Fatalf("expected real IP %q, got %q", "203.0.113.26", got)
	}
}

func TestResolveClientIPFallsBackToRemoteIPForTrustedProxyWithoutValidHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("X-Forwarded-For", "invalid")
	request.Header.Set("X-Real-IP", "also-invalid")

	got := resolveClientIP(request, parseTrustedProxies([]string{"10.0.0.10"}))

	if got != "10.0.0.10" {
		t.Fatalf("expected fallback remote IP %q, got %q", "10.0.0.10", got)
	}
}

func TestParseTrustedProxiesSupportsSingleIPsAndCIDRs(t *testing.T) {
	trustedProxies := parseTrustedProxies([]string{
		"10.0.0.10",
		"192.168.1.0/24",
		"2001:db8::1",
		"2001:db8:abcd::/48",
		"",
		"invalid",
	})

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "exact IPv4",
			ip:   "10.0.0.10",
			want: true,
		},
		{
			name: "different IPv4",
			ip:   "10.0.0.11",
			want: false,
		},
		{
			name: "IPv4 CIDR",
			ip:   "192.168.1.25",
			want: true,
		},
		{
			name: "outside IPv4 CIDR",
			ip:   "192.168.2.25",
			want: false,
		},
		{
			name: "exact IPv6",
			ip:   "2001:db8::1",
			want: true,
		},
		{
			name: "different IPv6",
			ip:   "2001:db8::2",
			want: false,
		},
		{
			name: "IPv6 CIDR",
			ip:   "2001:db8:abcd::123",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTrustedProxy(net.ParseIP(tt.ip), trustedProxies)
			if got != tt.want {
				t.Fatalf("expected trusted=%v for %q, got %v", tt.want, tt.ip, got)
			}
		})
	}
}
