package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/baxromumarov/go_shield/internal/clock"
	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
	jwt "github.com/golang-jwt/jwt/v5"
)

const bearerScheme = "Bearer"

var (
	errInvalidToken = errors.New("invalid token")
)

func Middleware(cfg config.JWTConfig) waf.Middleware {
	validator := newValidator(cfg)

	return middlewareWithValidator(cfg.Enabled, validator)
}

func middlewareWithValidator(enabled bool, validator validator) waf.Middleware {
	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !enabled || !validator.requiresAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

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

type validator struct {
	secret          []byte
	issuer          string
	audience        string
	protectedRoutes []string
	skipRoutes      []string
	now             clock.Clock
}

func newValidator(cfg config.JWTConfig) validator {
	return validator{
		secret:          []byte(cfg.Secret),
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		protectedRoutes: cfg.ProtectedRoutes,
		skipRoutes:      cfg.SkipRoutes,
		now:             clock.System,
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

	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	}
	if v.issuer != "" {
		options = append(options, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		options = append(options, jwt.WithAudience(v.audience))
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(
		token,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errInvalidToken
			}

			return v.secret, nil
		},
		options...,
	)
	if err != nil ||
		parsedToken == nil ||
		!parsedToken.Valid {
		return nil, errInvalidToken
	}

	return map[string]any(claims), nil
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
