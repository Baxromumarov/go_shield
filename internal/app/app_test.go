package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
)

func TestNewAppliesRouteGlobalRateLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := New(&config.Config{
		Backend: config.BackendConfig{
			URL: backend.URL,
		},
		RequestLimits: config.RequestLimits{
			DefaultMaxBodyBytes: 1 << 20,
		},
		RateLimits: config.RateLimitConfig{
			Enabled: true,
			Routes: map[string]config.TokenBucketRule{
				"/api/users/me": {
					Capacity:            1,
					RefillRatePerSecond: 0,
				},
			},
		},
		JWT: config.JWTConfig{
			Enabled: true,
			Secret:  "secret",
			ProtectedRoutes: []string{
				"/api/users",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to build app: %v", err)
	}

	userOneToken := signToken(t, "secret", "user-1")

	first := serveProtectedRequest(handler, userOneToken)
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request status %d, got %d", http.StatusOK, first.Code)
	}

	second := serveProtectedRequest(handler, userOneToken)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request status %d, got %d", http.StatusTooManyRequests, second.Code)
	}
}

func serveProtectedRequest(handler http.Handler, token string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, request)
	return recorder
}

func signToken(t *testing.T, secret, subject string) string {
	t.Helper()

	header := encodeJSON(t, map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	})
	claims := encodeJSON(t, map[string]any{
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signingInput := header + "." + claims

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature
}

func encodeJSON(t *testing.T, value map[string]any) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal json: %v", err)
	}

	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
