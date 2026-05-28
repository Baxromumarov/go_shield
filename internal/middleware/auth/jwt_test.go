package auth

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
	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareDoesNothingWhenDisabled(t *testing.T) {
	called := false
	handler := Middleware(config.JWTConfig{
		Enabled: false,
		ProtectedRoutes: []string{
			"/api/users",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestMiddlewareSkipsUnprotectedRoutes(t *testing.T) {
	called := false
	handler := Middleware(testJWTConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/public", nil)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestMiddlewareSkipRoutesOverrideProtectedRoutes(t *testing.T) {
	called := false
	handler := Middleware(config.JWTConfig{
		Enabled: true,
		Secret:  "secret",
		ProtectedRoutes: []string{
			"/api",
		},
		SkipRoutes: []string{
			"/api/auth/login",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestMiddlewareRejectsProtectedRouteWithoutBearerToken(t *testing.T) {
	assertUnauthorized(t, "", "/api/users")
	assertUnauthorized(t, "Basic abc", "/api/users")
	assertUnauthorized(t, "Bearer", "/api/users")
	assertUnauthorized(t, "Bearer token extra", "/api/users")
}

func TestMiddlewareAcceptsValidTokenAndStoresClaimsInContext(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "secret", map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}, map[string]any{
		"sub":  "user-123",
		"role": "admin",
		"exp":  now.Add(time.Hour).Unix(),
	})

	var userID string
	var role string
	handler := middlewareWithNow(testJWTConfig(), now)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ = r.Context().Value(waf.UserIDKey).(string)
		role, _ = r.Context().Value(waf.UserRoleKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	request.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if userID != "user-123" {
		t.Fatalf("expected user ID %q, got %q", "user-123", userID)
	}

	if role != "admin" {
		t.Fatalf("expected role %q, got %q", "admin", role)
	}
}

func TestMiddlewareRejectsExpiredToken(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "secret", map[string]any{
		"alg": "HS256",
	}, map[string]any{
		"sub": "user-123",
		"exp": now.Add(-time.Second).Unix(),
	})

	assertUnauthorizedToken(t, token, now)
}

func TestMiddlewareRejectsTokenWithoutExpiration(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "secret", map[string]any{
		"alg": "HS256",
	}, map[string]any{
		"sub": "user-123",
	})

	assertUnauthorizedToken(t, token, now)
}

func TestMiddlewareRejectsTokenBeforeNotBeforeTime(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "secret", map[string]any{
		"alg": "HS256",
	}, map[string]any{
		"sub": "user-123",
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(time.Minute).Unix(),
	})

	assertUnauthorizedToken(t, token, now)
}

func TestMiddlewareRejectsUnsignedOrUnexpectedAlgorithmToken(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "secret", map[string]any{
		"alg": "none",
	}, map[string]any{
		"sub": "user-123",
		"exp": now.Add(time.Hour).Unix(),
	})

	assertUnauthorizedToken(t, token, now)
}

func TestMiddlewareRejectsTokenWithInvalidSignature(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	token := signToken(t, "wrong-secret", map[string]any{
		"alg": "HS256",
	}, map[string]any{
		"sub": "user-123",
		"exp": now.Add(time.Hour).Unix(),
	})

	assertUnauthorizedToken(t, token, now)
}

func TestRequiresAuthUsesPathBoundary(t *testing.T) {
	validator := newValidator(config.JWTConfig{
		ProtectedRoutes: []string{
			"/api/users",
		},
	})

	if !validator.requiresAuth("/api/users") {
		t.Fatal("expected exact route to require auth")
	}

	if !validator.requiresAuth("/api/users/me") {
		t.Fatal("expected nested route to require auth")
	}

	if validator.requiresAuth("/api/users2") {
		t.Fatal("expected path with only partial prefix not to require auth")
	}
}

func assertUnauthorized(t *testing.T, authorization, path string) {
	t.Helper()

	called := false
	handler := Middleware(testJWTConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") != bearerScheme {
		t.Fatalf("expected WWW-Authenticate header %q, got %q", bearerScheme, recorder.Header().Get("WWW-Authenticate"))
	}
}

func assertUnauthorizedToken(t *testing.T, token string, now time.Time) {
	t.Helper()

	called := false
	handler := middlewareWithNow(testJWTConfig(), now)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	request.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func middlewareWithNow(cfg config.JWTConfig, now time.Time) waf.Middleware {
	validator := newValidator(cfg)
	validator.now = func() time.Time {
		return now
	}

	return middlewareWithValidator(cfg.Enabled, validator)
}

func testJWTConfig() config.JWTConfig {
	return config.JWTConfig{
		Enabled: true,
		Secret:  "secret",
		ProtectedRoutes: []string{
			"/api/users",
			"/api/orders",
		},
		SkipRoutes: []string{
			"/api/auth/login",
			"/api/auth/register",
		},
	}
}

func signToken(t *testing.T, secret string, header, claims map[string]any) string {
	t.Helper()

	encodedHeader := encodeJSON(t, header)
	encodedClaims := encodeJSON(t, claims)
	signingInput := encodedHeader + "." + encodedClaims

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
