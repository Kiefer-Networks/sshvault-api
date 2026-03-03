package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIP_TrustedProxyUsesXForwardedFor(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "203.0.113.50" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "203.0.113.50")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_UntrustedProxyKeepsRemoteAddr(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "192.168.1.100:54321" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "192.168.1.100:54321")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("X-Forwarded-For", "spoofed-ip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_MultipleCIDRs(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8, 172.16.0.0/12")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "8.8.8.8" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "8.8.8.8")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.16.5.1:9999"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_NoXForwardedForFallsBackToXRealIP(t *testing.T) {
	handler := TrustedRealIP("127.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "1.2.3.4" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "1.2.3.4")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Set("X-Real-Ip", "1.2.3.4")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_NoHeaders_KeepsRemoteAddr(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "10.0.0.1:5000" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "10.0.0.1:5000")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_EmptyCIDRs(t *testing.T) {
	handler := TrustedRealIP("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "10.0.0.1:5000" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "10.0.0.1:5000")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "spoofed")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_SingleIPWithoutCIDR(t *testing.T) {
	handler := TrustedRealIP("10.0.0.1")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "203.0.113.1" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "203.0.113.1")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_IPv6SingleAddress(t *testing.T) {
	handler := TrustedRealIP("::1")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "2001:db8::1" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "2001:db8::1")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:8080"
	req.Header.Set("X-Forwarded-For", "2001:db8::1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_MultipleXForwardedForTakesRightmost(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "5.6.7.8" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "5.6.7.8")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_XForwardedForWithTrailingComma(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "9.8.7.6" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "9.8.7.6")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "9.8.7.6, ")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_RemoteAddrWithoutPort(t *testing.T) {
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "8.8.4.4" {
			t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, "8.8.4.4")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	req.Header.Set("X-Forwarded-For", "8.8.4.4")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestTrustedRealIP_CallsNextHandler(t *testing.T) {
	called := false
	handler := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called")
	}
}

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		contains []string // IPs that should be in one of the networks
	}{
		{
			name:     "single CIDR",
			input:    "10.0.0.0/8",
			wantLen:  1,
			contains: []string{"10.0.0.1", "10.255.255.255"},
		},
		{
			name:     "multiple CIDRs",
			input:    "10.0.0.0/8, 172.16.0.0/12",
			wantLen:  2,
			contains: []string{"10.1.2.3", "172.16.0.1"},
		},
		{
			name:    "empty string",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "whitespace only",
			input:   "  ,  ,  ",
			wantLen: 0,
		},
		{
			name:     "single IP without CIDR",
			input:    "10.0.0.1",
			wantLen:  1,
			contains: []string{"10.0.0.1"},
		},
		{
			name:     "IPv6 without CIDR",
			input:    "::1",
			wantLen:  1,
			contains: []string{"::1"},
		},
		{
			name:    "invalid CIDR is skipped",
			input:   "not-a-cidr, 10.0.0.0/8",
			wantLen: 1,
		},
		{
			name:     "mixed valid and extra whitespace",
			input:    "  10.0.0.0/8 , 192.168.0.0/16  ",
			wantLen:  2,
			contains: []string{"10.0.0.1", "192.168.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets := parseCIDRs(tt.input)
			if len(nets) != tt.wantLen {
				t.Errorf("parseCIDRs(%q) returned %d networks, want %d", tt.input, len(nets), tt.wantLen)
			}
			for _, ipStr := range tt.contains {
				ip := net.ParseIP(ipStr)
				found := false
				for _, n := range nets {
					if n.Contains(ip) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %q to be contained in parsed CIDRs from %q", ipStr, tt.input)
				}
			}
		})
	}
}

func TestIsTrusted(t *testing.T) {
	nets := parseCIDRs("10.0.0.0/8, 192.168.0.0/16")

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", true},
		{"172.16.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := isTrusted(ip, nets)
			if got != tt.want {
				t.Errorf("isTrusted(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsTrusted_EmptyNets(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if isTrusted(ip, nil) {
		t.Error("isTrusted with nil nets should return false")
	}
	if isTrusted(ip, []*net.IPNet{}) {
		t.Error("isTrusted with empty nets should return false")
	}
}

func TestExtractRealIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	got := extractRealIP(req)
	if got != "5.6.7.8" {
		t.Errorf("extractRealIP = %q, want %q", got, "5.6.7.8")
	}
}

func TestExtractRealIP_XForwardedForSingle(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := extractRealIP(req)
	if got != "1.2.3.4" {
		t.Errorf("extractRealIP = %q, want %q", got, "1.2.3.4")
	}
}

func TestExtractRealIP_FallbackToXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "9.9.9.9")

	got := extractRealIP(req)
	if got != "9.9.9.9" {
		t.Errorf("extractRealIP = %q, want %q", got, "9.9.9.9")
	}
}

func TestExtractRealIP_XForwardedForTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	req.Header.Set("X-Real-Ip", "2.2.2.2")

	got := extractRealIP(req)
	if got != "1.1.1.1" {
		t.Errorf("extractRealIP = %q, want %q (X-Forwarded-For should take precedence)", got, "1.1.1.1")
	}
}

func TestExtractRealIP_NoHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	got := extractRealIP(req)
	if got != "" {
		t.Errorf("extractRealIP with no headers = %q, want empty", got)
	}
}

func TestExtractRealIP_XRealIPWithWhitespace(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "  3.3.3.3  ")

	got := extractRealIP(req)
	if got != "3.3.3.3" {
		t.Errorf("extractRealIP = %q, want %q", got, "3.3.3.3")
	}
}
