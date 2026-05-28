package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func NewReverseProxy(rawURL string) (http.Handler, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("Error while parsing rawURL: %w", err)
	}

	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("invalid backend URL %q: must include scheme and host", rawURL)
	}

	return httputil.NewSingleHostReverseProxy(target), nil
}
