package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type OAuthProvider interface {
	VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error)
}

type OAuthUserInfo struct {
	Provider   string
	ProviderID string
	Email      string
}

// --- Apple ---

type AppleOAuth struct {
	clientID string
	cache    *jwk.Cache
}

func NewAppleOAuth(clientID string) *AppleOAuth {
	ctx := context.Background()
	c := jwk.NewCache(ctx)
	_ = c.Register("https://appleid.apple.com/auth/keys", jwk.WithMinRefreshInterval(15*time.Minute))

	return &AppleOAuth{
		clientID: clientID,
		cache:    c,
	}
}

func (a *AppleOAuth) VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	set, err := a.cache.Get(ctx, "https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, fmt.Errorf("fetching Apple JWKS: %w", err)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithAudience(a.clientID),
	)

	token, err := parser.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("apple key %s not found in JWKS", kid)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("extracting raw key: %w", err)
		}
		return rawKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verifying Apple ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid Apple token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	// Apple may also encode email_verified as a string
	if !emailVerified {
		if ev, ok := claims["email_verified"].(string); ok && ev == "true" {
			emailVerified = true
		}
	}

	if sub == "" {
		return nil, fmt.Errorf("missing sub in Apple token")
	}

	if !emailVerified {
		return nil, fmt.Errorf("apple email not verified")
	}

	return &OAuthUserInfo{
		Provider:   "apple",
		ProviderID: sub,
		Email:      email,
	}, nil
}

// --- Google ---

type GoogleOAuth struct {
	clientID string
}

func NewGoogleOAuth(clientID string) *GoogleOAuth {
	return &GoogleOAuth{clientID: clientID}
}

func (g *GoogleOAuth) VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://oauth2.googleapis.com/tokeninfo?id_token="+idToken, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verifying Google token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token verification failed: status %d", resp.StatusCode)
	}

	var result struct {
		Sub      string `json:"sub"`
		Email    string `json:"email"`
		Aud      string `json:"aud"`
		Verified string `json:"email_verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding Google response: %w", err)
	}

	if result.Aud != g.clientID {
		return nil, fmt.Errorf("google token audience mismatch: got %s, want %s", result.Aud, g.clientID)
	}

	if result.Sub == "" {
		return nil, fmt.Errorf("missing sub in Google token")
	}

	if result.Verified != "true" {
		return nil, fmt.Errorf("google email not verified")
	}

	return &OAuthUserInfo{
		Provider:   "google",
		ProviderID: result.Sub,
		Email:      result.Email,
	}, nil
}
