package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baxromumarov/go_shield/internal/config"
)

func TestMiddlewareDoesNothingWhenDisabled(t *testing.T) {
	called := false
	handler := Middleware(config.CORSConfig{
		Enabled: false,
		AllowedHosts: []string{
			"api.example.com",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Host = "attacker.com"

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestMiddlewareRejectsInvalidHost(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "attacker.com"

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestMiddlewareRejectsDisallowedMethod(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/", nil)
	request.Host = "api.example.com"

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, recorder.Code)
	}

	if recorder.Header().Get("Allow") != "GET, POST, OPTIONS" {
		t.Fatalf("expected Allow header %q, got %q", "GET, POST, OPTIONS", recorder.Header().Get("Allow"))
	}
}

func TestMiddlewareAllowsRequestWithoutOrigin(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "api.example.com"

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}

	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("expected no CORS origin header, got %q", recorder.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestMiddlewareAllowsConfiguredOrigin(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Host = "api.example.com"
	request.Header.Set("Origin", "https://app.example.com")

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if recorder.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("expected allowed origin header, got %q", recorder.Header().Get("Access-Control-Allow-Origin"))
	}

	if recorder.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("expected credentials header %q, got %q", "true", recorder.Header().Get("Access-Control-Allow-Credentials"))
	}
}

func TestMiddlewareRejectsDisallowedOrigin(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Host = "api.example.com"
	request.Header.Set("Origin", "https://attacker.com")

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareHandlesValidPreflight(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/", nil)
	request.Host = "api.example.com"
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called for preflight")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}

	assertHeader(t, recorder, "Access-Control-Allow-Origin", "https://app.example.com")
	assertHeader(t, recorder, "Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	assertHeader(t, recorder, "Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
	assertHeader(t, recorder, "Access-Control-Allow-Credentials", "true")
	assertHeader(t, recorder, "Access-Control-Max-Age", "600")
}

func TestMiddlewareRejectsPreflightForDisallowedRequestedMethod(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/", nil)
	request.Host = "api.example.com"
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodDelete)

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareRejectsPreflightForDisallowedRequestedHeader(t *testing.T) {
	called := false
	handler := Middleware(testConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/", nil)
	request.Host = "api.example.com"
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "Authorization, X-Evil")

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareSupportsWildcardOriginWithoutCredentials(t *testing.T) {
	handler := Middleware(config.CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet},
		AllowCredentials: false,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://random.example.com")

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	assertHeader(t, recorder, "Access-Control-Allow-Origin", "*")
}

func testConfig() config.CORSConfig {
	return config.CORSConfig{
		Enabled: true,
		AllowedHosts: []string{
			"api.example.com",
		},
		AllowedOrigins: []string{
			"https://app.example.com",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Authorization",
			"Content-Type",
			"X-Request-ID",
		},
		AllowCredentials: true,
		MaxAgeSeconds:    600,
	}
}

func assertHeader(t *testing.T, recorder *httptest.ResponseRecorder, name, want string) {
	t.Helper()

	if got := recorder.Header().Get(name); got != want {
		t.Fatalf("expected %s header %q, got %q", name, want, got)
	}
}
