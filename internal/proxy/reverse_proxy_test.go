package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baxromumarov/go_shield/internal/config"
)

func TestNewReverseProxyWithConfigRejectsInvalidURL(t *testing.T) {
	_, err := NewReverseProxyWithConfig(config.BackendConfig{URL: "localhost:8081"})
	if err == nil {
		t.Fatal("expected invalid backend URL error")
	}
}

func TestNewReverseProxyWithConfigProxiesRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer backend.Close()

	handler, err := NewReverseProxyWithConfig(config.BackendConfig{
		URL:                          backend.URL,
		DialTimeoutSeconds:           1,
		ResponseHeaderTimeoutSeconds: 1,
		IdleConnTimeoutSeconds:       1,
	})
	if err != nil {
		t.Fatalf("expected proxy to build: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}

	body, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if string(body) != "/api/users" {
		t.Fatalf("expected proxied path %q, got %q", "/api/users", string(body))
	}
}
