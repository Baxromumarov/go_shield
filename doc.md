Core Architecture:
Client
  |
  v
GoShield WAF Proxy
  |
  |-- Request size limit
  |-- IP allow/block list
  |-- Rate limiter
  |-- JWT validator
  |-- SQLi/XSS scanner
  |-- Security logging
  |
  v
Backend API


Learn:
  Authorization header
  Content-Type
  X-Forwarded-For
  X-Real-IP
  Host
  Origin
  Referer
  User-Agent

1. OWASP Top 10 [https://owasp.org/www-project-top-ten/]

API Risks:
  BOLA — Broken Object Level Authorization
  Broken Authentication
  Broken Object Property Level Authorization
  Unrestricted Resource Consumption
  Broken Function Level Authorization
  Server Side Request Forgery
  Security Misconfiguration

Implement:
  SQL injection
  XSS
  Authentication
  Access control
  JWT attacks
  CORS
  SSRF
  File upload vulnerabilities
  API testing
  HTTP request smuggling

flowchart TD
    Client[Client] --> Server[GoShield HTTP Server]

    Server --> Pipeline[WAF Middleware Pipeline]

    Pipeline --> ReqID[Request ID / Logging Context]
    ReqID --> ClientIP[Client IP Resolver]
    ClientIP --> SizeLimit[Request Size Limit]
    SizeLimit --> IPList[IP Allow / Block List]
    IPList --> RateLimit[Rate Limiter]
    RateLimit --> CORS[CORS / Host / Origin Checks]
    CORS --> JWT[JWT Validator]
    JWT --> Scanner[SQLi / XSS / Payload Scanner]
    Scanner --> Proxy[Reverse Proxy]

    Proxy --> Backend[Backend API]
    Backend --> Proxy
    Proxy --> Logger[Security Logger]
    Logger --> Client

PLAN:
1. Request ID / base logging

Assign a request ID early so every later log has the same ID.

### 2. Client IP resolution

Resolve the real client IP from:

- `X-Forwarded-For`
- `X-Real-IP`
- `RemoteAddr`

But be careful: only trust `X-Forwarded-For` if the request came from a trusted proxy/load balancer. Otherwise attackers can spoof it.

### 3. Request size limit

Do this early to avoid memory/resource exhaustion.

For example:

- `GET`, `HEAD`, `OPTIONS`: body should usually be `0`
- `POST`, `PUT`, `PATCH`: route-specific size
- file uploads: larger but special handling

### 4. IP allow/block list

Cheap check, so do it before expensive validation.

### 5. Rate limiter

Also early. Prevent brute force, scraping, login attacks, upload abuse.

Keys could be:

```txt
ip
user
user_or_ip
jwt_subject
api_key
```

### 6. CORS / Host / Origin checks

Good place to reject suspicious origins, invalid hosts, or unexpected methods.

### 7. JWT validator

Only apply this to routes that require auth. Some routes like `/api/auth/login` and `/api/auth/register` should usually skip JWT validation.

### 8. SQLi / XSS / payload scanner

This may require reading query params, headers, and body. Be careful with body handling because the reverse proxy still needs to forward the body to the backend.

Common approach:

1. Read body up to configured max size.
2. Scan it.
3. Restore body:

```go
r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
```

### 9. Reverse proxy to backend

Only safe/accepted requests reach the backend.

### 10. Security logging

Log both rejected and proxied requests.