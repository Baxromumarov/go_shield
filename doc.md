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