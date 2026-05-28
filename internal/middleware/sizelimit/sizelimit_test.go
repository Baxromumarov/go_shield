package sizelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baxromumarov/go_shield/internal/config"
)

func TestMiddlewareRejectsBodyWhenLimitIsZero(t *testing.T) {
	called := false
	handler := Middleware(config.RequestLimits{
		Methods: map[string]int{
			http.MethodGet: 0,
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("unexpected body"))

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, recorder.Code)
	}
}

func TestMiddlewareAllowsRequestWithoutBodyWhenLimitIsZero(t *testing.T) {
	called := false
	handler := Middleware(
		config.RequestLimits{
			Methods: map[string]int{
				http.MethodGet: 0,
			},
		},
	)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestMiddlewareRejectsChunkedBodyWhenLimitIsZero(t *testing.T) {
	called := false
	handler := Middleware(config.RequestLimits{
		Methods: map[string]int{
			http.MethodGet: 0,
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("unexpected body"))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}

	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("expected next handler not to be called")
	}

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, recorder.Code)
	}
}

func TestMiddlewareSkipsLimitWhenNegative(t *testing.T) {
	called := false
	handler := Middleware(config.RequestLimits{
		Methods: map[string]int{
			http.MethodPost: -1,
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))

	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}
