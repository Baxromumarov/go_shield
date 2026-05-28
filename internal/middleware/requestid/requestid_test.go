package requestid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareSetsRequestIDHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := Middleware()(next)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(recorder, request)

	requestID := recorder.Header().Get(HeaderName)
	if requestID == "" {
		t.Fatal("expected request ID header to be set")
	}

	if !strings.HasPrefix(requestID, "req_") {
		t.Fatalf("expected request ID to have req_ prefix, got %q", requestID)
	}
}

func TestMiddlewareAddsRequestIDToContext(t *testing.T) {
	var contextRequestID string

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextRequestID, _ = r.Context().Value(waf.RequestIDKey).(string)
	})
	handler := Middleware()(next)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(recorder, request)

	headerRequestID := recorder.Header().Get(HeaderName)
	if contextRequestID == "" {
		t.Fatal("expected request ID to be added to request context")
	}

	if contextRequestID != headerRequestID {
		t.Fatalf("expected context request ID %q to match header request ID %q", contextRequestID, headerRequestID)
	}
}

func TestGenerateRequestID(t *testing.T) {
	requestID := generateRequestID()

	if len(requestID) != len("req_")+32 {
		t.Fatalf("expected request ID length %d, got %d", len("req_")+32, len(requestID))
	}

	if !strings.HasPrefix(requestID, "req_") {
		t.Fatalf("expected request ID to have req_ prefix, got %q", requestID)
	}

	for _, char := range strings.TrimPrefix(requestID, "req_") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Fatalf("expected request ID to contain only lowercase hex chars, got %q", requestID)
		}
	}
}
