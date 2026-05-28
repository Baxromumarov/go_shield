package logging

import (
	"log"
	"net/http"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.bytes += n
	return n, err
}

func Middleware(cfg config.SecurityLogConfig) waf.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			wrappedWriter := newResponseWriter(w)

			next.ServeHTTP(wrappedWriter, r)

			requestID, _ := r.Context().Value(waf.RequestIDKey).(string)

			log.Printf(
				"request_id=%s method=%s path=%s status=%d duration=%s bytes=%d",
				requestID,
				r.Method,
				r.URL.Path,
				wrappedWriter.statusCode,
				time.Since(start),
				wrappedWriter.bytes,
			)
		})

	}
}
