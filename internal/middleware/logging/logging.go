package logging

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

const (
	colorReset  = "\x1b[0m"
	colorBold   = "\x1b[1m"
	colorDim    = "\x1b[2m"
	colorCyan   = "\x1b[36m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorRed    = "\x1b[31m"
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

			log.Print(formatRequestLog(
				time.Now().Format("15:04:05.000"),
				r.Method,
				requestTarget(r),
				wrappedWriter.statusCode,
				formatDuration(time.Since(start)),
				formatBytes(wrappedWriter.bytes),
				requestID,
			))
		})

	}
}

func formatRequestLog(timestamp, method, target string, statusCode int, duration, bytes, requestID string) string {
	methodColor := colorForMethod(method)
	statusColor := colorForStatus(statusCode)

	return fmt.Sprintf(
		"%s[%s]%s %s%s%s %s %s%d %s%s %s %s %sreq=%s%s",
		colorDim,
		timestamp,
		colorReset,
		methodColor+colorBold,
		method,
		colorReset,
		truncate(target, 36),
		statusColor+colorBold,
		statusCode,
		http.StatusText(statusCode),
		colorReset,
		duration,
		bytes,
		colorDim,
		shortRequestID(requestID),
		colorReset,
	)
}

func requestTarget(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}

	return r.URL.Path + "?" + r.URL.RawQuery
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return d.String()
	} else if d < time.Second {
		return fmt.Sprintf("%.0fms", d.Seconds()*1000)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func formatBytes(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func shortRequestID(requestID string) string {
	if requestID == "" {
		return "-"
	}

	const prefix = "req_"
	if strings.HasPrefix(requestID, prefix) && len(requestID) > len(prefix)+12 {
		return prefix + requestID[len(prefix):len(prefix)+12]
	}

	if len(requestID) > 16 {
		return requestID[:16]
	}

	return requestID
}

func colorForMethod(method string) string {
	switch method {
	case http.MethodGet:
		return colorCyan
	case http.MethodPost:
		return colorGreen
	case http.MethodPut, http.MethodPatch:
		return colorYellow
	case http.MethodDelete:
		return colorRed
	default:
		return colorReset
	}
}

func colorForStatus(statusCode int) string {
	switch {
	case statusCode >= 500:
		return colorRed
	case statusCode >= 400:
		return colorYellow
	case statusCode >= 300:
		return colorCyan
	default:
		return colorGreen
	}
}
