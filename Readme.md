# GoShield

GoShield is a learning WAF/reverse-proxy written in Go. It accepts HTTP
traffic, applies a middleware security pipeline, and forwards allowed requests
to a configured backend.

NOTE: This is still not a production WAF. It is a practical project for studying
reverse proxies, middleware ordering, request validation, rate limiting, JWT
authentication, and shared security state.

## Features

- Reverse proxy with backend URL validation, transport timeouts, and 502 error handling.
- Request IDs and structured request logging.
- Trusted-proxy-aware client IP resolution.
- Static IP/CIDR blocklist.
- Request body limits by method and route.
- CORS host, origin, method, and header policy checks.
- JWT authentication using `github.com/golang-jwt/jwt/v5`.
- Per-route rate limits keyed by client IP, user ID, user-or-IP, or globally.
- SQLi/XSS-style payload scanner for query strings, headers, and bodies.
- Runtime scanner blocklist with TTL.
- Shared state backend: in-process memory or Redis.

## Run

Start a test backend:

```sh
go run .
```

Start GoShield:

```sh
go run ./cmd/goshield
```

Run tests:

```sh
go test ./...
```

## Configuration

The default config lives in `config.yaml`.

Memory state is the default and is simplest for local development:

```yaml
state:
    backend: "memory"
```

Use Redis when multiple GoShield processes must share rate-limit buckets and
scanner runtime blocks:

```yaml
state:
    backend: "redis"
    namespace: "goshield"
    redis:
        addr: "localhost:6379"
        password: ""
        db: 0
```

Rate limits are configured per route. By default, buckets are scoped by client
IP so one client cannot consume the route bucket for everyone:

```yaml
rate_limits:
    enabled: true
    key_by: "client_ip" # client_ip, user_id, user_or_ip, or global
    fail_open: false
    routes:
        "/api/auth/login":
            capacity: 100
            refill_rate_per_second: 10
```

JWT validation requires HS256, an `exp` claim, and a matching signature.
Issuer and audience checks are optional:

```yaml
jwt:
    enabled: true
    secret: "replace-this-with-a-long-random-secret"
    issuer: "goshield"
    audience: "api"
```

## Limits

The scanner is regex-based. It is useful as a teaching component, but it will
miss attacks and can block valid requests. Real production WAFs need richer
parsing, tuned rules, observability, and a false-positive workflow.

The Redis backend shares state, but it is not a complete distributed security
platform. Production deployments still need metrics, alerts, secret management,
TLS, configuration review, and careful fail-open/fail-closed decisions.
