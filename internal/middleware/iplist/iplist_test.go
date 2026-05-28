package iplist

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareAllowsClientIPWhenBlockListIsEmpty(t *testing.T) {
	called := false
	handler := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := requestWithClientIP("203.0.113.10")

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestMiddlewareAllowsClientIPWhenNotBlocked(t *testing.T) {
	called := false
	handler := Middleware([]string{
		"198.51.100.10",
		"10.0.0.0/24",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := requestWithClientIP("203.0.113.10")

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestMiddlewareBlocksMatchingClientIPs(t *testing.T) {
	tests := []struct {
		name      string
		blockList []string
		clientIP  string
	}{
		{
			name:      "exact IPv4",
			blockList: []string{"203.0.113.10"},
			clientIP:  "203.0.113.10",
		},
		{
			name:      "IPv4 CIDR",
			blockList: []string{"203.0.113.0/24"},
			clientIP:  "203.0.113.10",
		},
		{
			name:      "exact IPv6",
			blockList: []string{"2001:db8::10"},
			clientIP:  "2001:db8::10",
		},
		{
			name:      "IPv6 CIDR",
			blockList: []string{"2001:db8::/32"},
			clientIP:  "2001:db8::10",
		},
		{
			name:      "trimmed block list value",
			blockList: []string{" 203.0.113.10 "},
			clientIP:  "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := Middleware(tt.blockList)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			recorder := httptest.NewRecorder()
			request := requestWithClientIP(tt.clientIP)

			handler.ServeHTTP(recorder, request)

			if called {
				t.Fatal("expected next handler not to be called")
			}

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
			}
		})
	}
}

func TestMiddlewareRejectsMissingOrInvalidClientIP(t *testing.T) {
	tests := []struct {
		name    string
		request *http.Request
	}{
		{
			name:    "missing client IP context",
			request: httptest.NewRequest(http.MethodGet, "/", nil),
		},
		{
			name:    "invalid client IP context",
			request: requestWithClientIP("not-an-ip"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := Middleware([]string{"203.0.113.10"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tt.request)

			if called {
				t.Fatal("expected next handler not to be called")
			}

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
			}
		})
	}
}

func TestParseIPNetsSupportsExactIPsAndCIDRs(t *testing.T) {
	blocked := parseIPNets([]string{
		"203.0.113.10",
		"198.51.100.0/24",
		"2001:db8::10",
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
			ip:   "203.0.113.10",
			want: true,
		},
		{
			name: "different IPv4",
			ip:   "203.0.113.11",
			want: false,
		},
		{
			name: "IPv4 CIDR",
			ip:   "198.51.100.25",
			want: true,
		},
		{
			name: "outside IPv4 CIDR",
			ip:   "198.51.101.25",
			want: false,
		},
		{
			name: "exact IPv6",
			ip:   "2001:db8::10",
			want: true,
		},
		{
			name: "different IPv6",
			ip:   "2001:db8::11",
			want: false,
		},
		{
			name: "IPv6 CIDR",
			ip:   "2001:db8:abcd::25",
			want: true,
		},
		{
			name: "outside IPv6 CIDR",
			ip:   "2001:db8:abce::25",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsIP(blocked, net.ParseIP(tt.ip))
			if got != tt.want {
				t.Fatalf("expected containsIP=%v for %q, got %v", tt.want, tt.ip, got)
			}
		})
	}
}

func TestParseIPNetsIgnoresInvalidValues(t *testing.T) {
	blocked := parseIPNets([]string{
		"",
		" ",
		"invalid",
		"999.999.999.999",
		"203.0.113.0/99",
	})

	if len(blocked) != 0 {
		t.Fatalf("expected no parsed IP nets, got %d", len(blocked))
	}
}

func TestContainsIPReturnsFalseForEmptyBlockList(t *testing.T) {
	if containsIP(nil, net.ParseIP("203.0.113.10")) {
		t.Fatal("expected empty block list not to contain IP")
	}
}

func requestWithClientIP(clientIP string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(request.Context(), waf.ClientIPKey, clientIP)

	return request.WithContext(ctx)
}
