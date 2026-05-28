// cheap ip checking, if incoming ip is
// in block list just return error
package iplist

import (
	"net"
	"net/http"
	"strings"

	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(bannedIPs []string) waf.Middleware {
	blockedIPs := parseIPNets(bannedIPs)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := waf.GetCtxKey(r, waf.ClientIPKey)
			parsedClientIP := net.ParseIP(clientIP)
			if parsedClientIP == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			if containsIP(blockedIPs, parsedClientIP) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func parseIPNets(ips []string) []*net.IPNet {
	ipNets := make([]*net.IPNet, 0, len(ips))

	for _, rawIP := range ips {
		rawIP = strings.TrimSpace(rawIP)
		if rawIP == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(rawIP)
		if err == nil {
			ipNets = append(ipNets, ipNet)
			continue
		}

		ip := net.ParseIP(rawIP)
		if ip == nil {
			continue
		}

		bits := 32
		if ip.To4() == nil {
			bits = 128
		}

		ipNets = append(ipNets, &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(bits, bits),
		})
	}

	return ipNets
}

func containsIP(blocked []*net.IPNet, clientIP net.IP) bool {
	for _, b := range blocked {
		if b.Contains(clientIP) {
			return true
		}
	}

	return false
}
