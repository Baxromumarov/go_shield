package logging

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareLogsRequest(t *testing.T) {
	var logOutput bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&logOutput)
	log.SetFlags(0)
	defer log.SetOutput(originalOutput)
	defer log.SetFlags(originalFlags)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	})
	handler := Middleware(config.SecurityLogConfig{Enabled: true})(next)

	request := httptest.NewRequest(http.MethodPost, "/users", nil)
	ctx := context.WithValue(request.Context(), waf.RequestIDKey, "req_test")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request.WithContext(ctx))

	output := logOutput.String()
	assertLogContains(t, output, "request_id=req_test")
	assertLogContains(t, output, "method=POST")
	assertLogContains(t, output, "path=/users")
	assertLogContains(t, output, "status=201")
	assertLogContains(t, output, "bytes=7")
	assertLogContains(t, output, "duration=")
}

func TestMiddlewareDoesNotLogWhenDisabled(t *testing.T) {
	var logOutput bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&logOutput)
	log.SetFlags(0)
	defer log.SetOutput(originalOutput)
	defer log.SetFlags(originalFlags)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(config.SecurityLogConfig{Enabled: false})(next)

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if logOutput.String() != "" {
		t.Fatalf("expected no log output when logging is disabled, got %q", logOutput.String())
	}
}

func assertLogContains(t *testing.T, output, want string) {
	t.Helper()

	if !strings.Contains(output, want) {
		t.Fatalf("expected log output to contain %q, got %q", want, output)
	}
}
