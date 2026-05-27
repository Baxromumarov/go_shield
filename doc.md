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
