package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
)

func NewReverseProxy(rawURL string) (http.Handler, error) {
	return NewReverseProxyWithConfig(config.BackendConfig{URL: rawURL})
}

func NewReverseProxyWithConfig(cfg config.BackendConfig) (http.Handler, error) {
	rawURL := cfg.URL
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("error while parsing backend URL: %w", err)
	}

	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("invalid backend URL %q: must include scheme and host", rawURL)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   secondsOrDefault(cfg.DialTimeoutSeconds, 5),
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: secondsOrDefault(cfg.ResponseHeaderTimeoutSeconds, 10),
		IdleConnTimeout:       secondsOrDefault(cfg.IdleConnTimeoutSeconds, 90),
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Warn("backend proxy error", "method", r.Method, "path", r.URL.Path, "backend", target.String(), "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy, nil
}

func secondsOrDefault(seconds, defaultSeconds int) time.Duration {
	if seconds <= 0 {
		seconds = defaultSeconds
	}

	return time.Duration(seconds) * time.Second
}
