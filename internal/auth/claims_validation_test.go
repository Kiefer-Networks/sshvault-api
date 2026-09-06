package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestAccessClaimsRequiredAndValidated(t *testing.T) {
	m := newTestJWTManager(t)
	for _, tc := range []struct {
		name, key string
		value     any
		remove    bool
	}{
		{"issuer missing", "iss", nil, true}, {"issuer wrong", "iss", "other", false},
		{"audience missing", "aud", nil, true}, {"audience wrong", "aud", []string{"other"}, false},
		{"subject missing", "sub", nil, true}, {"subject empty", "sub", "", false},
		{"expiry missing", "exp", nil, true}, {"expiry null", "exp", nil, false}, {"expiry string", "exp", "9999999999", false},
		{"issued at missing", "iat", nil, true}, {"issued at null", "iat", nil, false}, {"issued at future", "iat", time.Now().Add(time.Hour).Unix(), false},
		{"version missing", "session_version", nil, true}, {"version null", "session_version", nil, false}, {"version negative", "session_version", -1, false}, {"version string", "session_version", "0", false}, {"version fractional", "session_version", 0.5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "sshvault", "aud": []string{"sshvault-api"}, "sub": uuid.NewString(), "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Add(-time.Second).Unix(), "session_version": 0}
			if tc.remove {
				delete(claims, tc.key)
			} else {
				claims[tc.key] = tc.value
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.ValidateAccessToken(token); err == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
}
