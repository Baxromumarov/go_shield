// High level logic: [Find the real client IP -> store it in request context -> let the next middleware continue]
package clientip

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(trustedProxies []string) waf.Middleware {
	trustedNets := parseTrustedProxies(trustedProxies)

	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		clientIP := resolveClientIP(r, trustedNets)

		// store the client IP in context
		// later can be read
		ctx := context.WithValue(r.Context(), waf.ClientIPKey, clientIP)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func resolveClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP := parseRemoteIP(r.RemoteAddr)
	if remoteIP == nil {
		return ""
	}

	// If direct peer is not trusted ignore headers
	// If the request did not come from a trusted proxy, then headers like these are ignored:
	// Example:
	//        X-Forwarded-For: 1.2.3.4
	//        X-Real-IP: 1.2.3.4
	if !isTrustedProxy(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	// if it is trusted
	// we can forward it
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		parts := strings.SplitSeq(forwardedFor, ",")
		for part := range parts {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip != nil {
				return ip.String()
			}
		}
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		ip := net.ParseIP(strings.TrimSpace(realIP))
		if ip != nil {
			return ip.String()
		}
	}

	return remoteIP.String()
}

func parseRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	return net.ParseIP(host)
}

func parseTrustedProxies(proxies []string) []*net.IPNet {
	trusted := make([]*net.IPNet, 0, len(proxies))

	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(proxy)
		if err == nil {
			trusted = append(trusted, ipNet)
			continue
		}

		ip := net.ParseIP(proxy)
		if ip == nil {
			continue
		}

		bits := 32
		if ip.To4() == nil {
			bits = 128
		}

		trusted = append(trusted, &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(bits, bits),
		})
	}

	return trusted
}

func isTrustedProxy(ip net.IP, trustedProxies []*net.IPNet) bool {
	for _, proxy := range trustedProxies {
		if proxy.Contains(ip) {
			return true
		}
	}

	return false
}
