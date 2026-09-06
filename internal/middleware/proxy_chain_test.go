package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardedChainWalksOnlyExplicitlyTrustedHops(t *testing.T) {
	for _, tc := range []struct {
		xff, want string
		status    int
	}{
		{"203.0.113.7, 10.0.0.2", "203.0.113.7", 200}, {"198.51.100.4, 192.0.2.6, 10.0.0.2", "192.0.2.6", 200}, {"garbage, 10.0.0.2", "", 400}, {"203.0.113.7,", "", 400}, {"203.0.113.7:444", "", 400}, {"[2001:db8::1]", "", 400},
	} {
		t.Run(tc.xff, func(t *testing.T) {
			called := false
			h := TrustedRealIP("10.0.0.0/8")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.RemoteAddr != tc.want {
					t.Errorf("client=%q want %q", r.RemoteAddr, tc.want)
				}
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "10.0.0.1:99"
			r.Header.Set("X-Forwarded-For", tc.xff)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Errorf("status=%d", w.Code)
			}
			if tc.status == 400 && called {
				t.Error("invalid forwarding reached handler")
			}
		})
	}
}
