package middleware

import (
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
				if realIP := extractRealIP(r); realIP != "" {
					r.RemoteAddr = realIP
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

// extractRealIP picks the rightmost non-private IP from X-Forwarded-For,
// falling back to X-Real-Ip.
func extractRealIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return ""
}
