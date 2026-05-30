package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/state"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareDoesNothingWhenDisabled(t *testing.T) {
	called := false
	handler := Middleware(config.ScannerConfig{
		Enabled:   false,
		ScanQuery: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestMiddlewareAllowsCleanRequest(t *testing.T) {
	called := false
	handler := Middleware(testScannerConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/?q=hello", strings.NewReader(`{"name":"alice"}`))
	request.Header.Set("User-Agent", "GoShield test")

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestMiddlewareBlocksSQLInjectionInQuery(t *testing.T) {
	recorder := serveScannerRequest(
		testScannerConfig(),
		httptest.NewRequest(http.MethodGet, "/users?id=1%20OR%201=1", nil),
	)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareBlocksEncodedXSSInQuery(t *testing.T) {
	recorder := serveScannerRequest(
		testScannerConfig(),
		httptest.NewRequest(http.MethodGet, "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", nil),
	)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareBlocksAttackInHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("User-Agent", `<img src=x onerror=alert(1)>`)

	recorder := serveScannerRequest(testScannerConfig(), request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareBlocksSQLInjectionInBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"filter":"' UNION SELECT password FROM users"}`))

	recorder := serveScannerRequest(testScannerConfig(), request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareBlocksXSSInBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"bio":"<script>alert(1)</script>"}`))

	recorder := serveScannerRequest(testScannerConfig(), request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestMiddlewareRestoresBodyForNextHandler(t *testing.T) {
	const body = `{"name":"alice"}`
	var nextBody string

	handler := Middleware(testScannerConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read restored body: %v", err)
		}

		nextBody = string(data)
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if nextBody != body {
		t.Fatalf("expected restored body %q, got %q", body, nextBody)
	}
}

func TestMiddlewareRespectsScanToggles(t *testing.T) {
	cfg := config.ScannerConfig{
		Enabled:     true,
		ScanQuery:   false,
		ScanHeaders: false,
		ScanBody:    false,
	}

	called := false
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", strings.NewReader(`' OR 1=1`))
	request.Header.Set("User-Agent", `<script>alert(1)</script>`)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestMiddlewareDoesNotScanAuthorizationHeader(t *testing.T) {
	cfg := config.ScannerConfig{
		Enabled:     true,
		ScanHeaders: true,
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer <script>alert(1)</script>")

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestMiddlewareAddsAttackingClientIPToRuntimeBlocklist(t *testing.T) {
	called := 0
	handler := Middleware(testScannerConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	attack := requestWithClientIP(http.MethodGet, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", "203.0.113.10")
	attackRecorder := httptest.NewRecorder()

	handler.ServeHTTP(attackRecorder, attack)

	if attackRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected attack status %d, got %d", http.StatusForbidden, attackRecorder.Code)
	}

	cleanSameIP := requestWithClientIP(http.MethodGet, "/?q=hello", "", "203.0.113.10")
	cleanSameIPRecorder := httptest.NewRecorder()

	handler.ServeHTTP(cleanSameIPRecorder, cleanSameIP)

	if cleanSameIPRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected blocked IP status %d, got %d", http.StatusForbidden, cleanSameIPRecorder.Code)
	}

	cleanDifferentIP := requestWithClientIP(http.MethodGet, "/?q=hello", "", "203.0.113.11")
	cleanDifferentIPRecorder := httptest.NewRecorder()

	handler.ServeHTTP(cleanDifferentIPRecorder, cleanDifferentIP)

	if cleanDifferentIPRecorder.Code != http.StatusOK {
		t.Fatalf("expected different IP status %d, got %d", http.StatusOK, cleanDifferentIPRecorder.Code)
	}

	if called != 1 {
		t.Fatalf("expected next handler to be called once, got %d", called)
	}
}

func TestRuntimeBlocklistExpires(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	store := state.NewMemoryWithClock(func() time.Time {
		return now
	})
	blocklist := newBlocklist(config.ScannerConfig{
		RuntimeBlockTTLSeconds: 1,
	}, store)

	request := requestWithClientIP(http.MethodGet, "/", "", "203.0.113.10")
	if err := blocklist.add(request); err != nil {
		t.Fatalf("expected blocklist add to succeed: %v", err)
	}

	blocked, err := blocklist.contains(request)
	if err != nil {
		t.Fatalf("expected blocklist lookup to succeed: %v", err)
	}
	if !blocked {
		t.Fatal("expected client IP to be blocked")
	}

	now = now.Add(2 * time.Second)

	blocked, err = blocklist.contains(request)
	if err != nil {
		t.Fatalf("expected blocklist lookup to succeed: %v", err)
	}
	if blocked {
		t.Fatal("expected client IP block to expire")
	}
}

func TestMaliciousDetectsCommonSQLiAndXSSPayloads(t *testing.T) {
	tests := []string{
		"' OR 1=1",
		"UNION SELECT password FROM users",
		"1; DROP TABLE users",
		"admin'--",
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if !malicious(tt) {
				t.Fatalf("expected payload to be detected: %q", tt)
			}
		})
	}
}

func requestWithClientIP(method, target, body, clientIP string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(request.Context(), waf.ClientIPKey, clientIP)

	return request.WithContext(ctx)
}

func serveScannerRequest(cfg config.ScannerConfig, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(recorder, request)
	return recorder
}

func testScannerConfig() config.ScannerConfig {
	return config.ScannerConfig{
		Enabled:     true,
		ScanQuery:   true,
		ScanHeaders: true,
		ScanBody:    true,
	}
}
