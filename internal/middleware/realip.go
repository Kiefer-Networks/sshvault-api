package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedRealIP extracts the client IP from X-Forwarded-For only when the
// direct connection originates from a trusted proxy network. Untrusted callers
// keep their RemoteAddr as-is, preventing IP spoofing.
func TrustedRealIP(trustedCIDRs string) func(http.Handler) http.Handler {
	nets := parseCIDRs(trustedCIDRs)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			if remoteIP == "" {
				remoteIP = r.RemoteAddr
			}

			ip := net.ParseIP(remoteIP)
			if ip != nil && isTrusted(ip, nets) {
				forwarded, err := forwardedChain(r)
				if err != nil {
					respondJSONError(w, http.StatusBadRequest, "invalid forwarding address")
					return
				}
				current := ip
				for i := len(forwarded) - 1; i >= 0 && isTrusted(current, nets); i-- {
					current = forwarded[i]
				}
				if len(forwarded) > 0 {
					r.RemoteAddr = current.String()
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func parseCIDRs(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		if _, cidr, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}

func isTrusted(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Validate the complete presented chain, then trust only configured hops.
func forwardedChain(r *http.Request) ([]net.IP, error) {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		values = r.Header.Values("X-Real-Ip")
		if len(values) > 1 {
			return nil, fmt.Errorf("multiple real IP values")
		}
	}
	var result []net.IP
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip == nil {
				return nil, fmt.Errorf("invalid IP")
			}
			result = append(result, ip)
		}
	}
	return result, nil
}
