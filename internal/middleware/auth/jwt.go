package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

const bearerScheme = "Bearer"

var (
	errInvalidToken = errors.New("invalid token")
	errExpiredToken = errors.New("expired token")
)

func Middleware(cfg config.JWTConfig) waf.Middleware {
	validator := newValidator(cfg)

	return middlewareWithValidator(cfg.Enabled, validator)
}

func middlewareWithValidator(enabled bool, validator validator) waf.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled || !validator.requiresAuth(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// I guess this is most common method for JWT
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				unauthorized(w)
				return
			}

			claims, err := validator.validate(token)
			if err != nil {
				unauthorized(w)
				return
			}

			ctx := contextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type validator struct {
	secret          []byte
	protectedRoutes []string
	skipRoutes      []string
	now             func() time.Time
}

func newValidator(cfg config.JWTConfig) validator {
	return validator{
		secret:          []byte(cfg.Secret),
		protectedRoutes: cfg.ProtectedRoutes,
		skipRoutes:      cfg.SkipRoutes,
		now:             time.Now,
	}
}

func (v validator) requiresAuth(path string) bool {
	for _, route := range v.skipRoutes {
		if routeMatches(route, path) {
			return false
		}
	}

	for _, route := range v.protectedRoutes {
		if routeMatches(route, path) {
			return true
		}
	}

	return false
}

func (v validator) validate(token string) (map[string]any, error) {
	if len(v.secret) == 0 {
		return nil, errInvalidToken
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidToken
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errInvalidToken
	}

	alg, _ := header["alg"].(string)
	if alg != "HS256" {
		return nil, errInvalidToken
	}

	if !validSignature(parts[0]+"."+parts[1], parts[2], v.secret) {
		return nil, errInvalidToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalidToken
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errInvalidToken
	}

	if err := v.validateTimeClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (v validator) validateTimeClaims(claims map[string]any) error {
	now := v.now().Unix()

	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return errInvalidToken
	}

	if exp <= now {
		return errExpiredToken
	}

	// nbf = not before
	// It is a standard JWT time claim that says:
	// {This token must not be accepted before this Unix timestamp.}
	if nbf, ok := numericClaim(claims, "nbf"); ok && nbf > now {
		return errInvalidToken
	}

	return nil
}

func validSignature(signingInput, encodedSignature string, secret []byte) bool {
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)

	return hmac.Equal(signature, expected)
}

func bearerToken(headerValue string) (string, bool) {
	parts := strings.Fields(headerValue)
	if len(parts) != 2 || !strings.EqualFold(parts[0], bearerScheme) || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}

func contextWithClaims(ctx context.Context, claims map[string]any) context.Context {
	if subject, _ := claims["sub"].(string); subject != "" {
		ctx = context.WithValue(ctx, waf.UserIDKey, subject)
	}

	if role, _ := claims["role"].(string); role != "" {
		ctx = context.WithValue(ctx, waf.UserRoleKey, role)
	}

	return ctx
}

func numericClaim(claims map[string]any, name string) (int64, bool) {
	value, ok := claims[name]
	if !ok {
		return 0, false
	}

	switch v := value.(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func routeMatches(route, path string) bool {
	route = strings.TrimSpace(route)
	if route == "" {
		return false
	}

	if route == path {
		return true
	}

	return strings.HasPrefix(path, strings.TrimRight(route, "/")+"/")
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", bearerScheme)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
