package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware() waf.Middleware {
	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		requestID := generateRequestID()

		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), waf.RequestIDKey, requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const HeaderName = "X-Request-ID"

func generateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unknown"
	}

	return "req_" + hex.EncodeToString(b[:])
}
