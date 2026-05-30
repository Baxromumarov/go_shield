// Find the real client IP, stash it in context, move on with life.
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
		ctx := context.WithValue(r.Context(), waf.ClientIPKey, clientIP)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func resolveClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP := parseRemoteIP(r.RemoteAddr)
	if remoteIP == nil {
		return ""
	}

	// If the direct peer is not trusted, ignore forwarded headers. Nice try.
	if !isTrustedProxy(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		if ip, ok := clientIPFromForwardedFor(forwardedFor, trustedProxies); ok {
			return ip
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

func clientIPFromForwardedFor(forwardedFor string, trustedProxies []*net.IPNet) (string, bool) {
	parts := strings.Split(forwardedFor, ",")
	leftmostValid := ""

	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}

		leftmostValid = ip.String()
		if !isTrustedProxy(ip, trustedProxies) {
			return ip.String(), true
		}
	}

	if leftmostValid != "" {
		return leftmostValid, true
	}

	return "", false
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
