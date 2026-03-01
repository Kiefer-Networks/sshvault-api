package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	teamID   string
	clientID string
}

type appleJWKS struct {
	Keys []json.RawMessage `json:"keys"`
}

func NewAppleOAuth(teamID, clientID string) *AppleOAuth {
	return &AppleOAuth{teamID: teamID, clientID: clientID}
}

func (a *AppleOAuth) VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithAudience(a.clientID),
	)

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return fetchApplePublicKey(ctx, kid)
	}

	token, err := parser.Parse(idToken, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("verifying Apple ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid Apple token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	if sub == "" {
		return nil, fmt.Errorf("missing sub in Apple token")
	}

	return &OAuthUserInfo{
		Provider:   "apple",
		ProviderID: sub,
		Email:      email,
	}, nil
}

func fetchApplePublicKey(ctx context.Context, kid string) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching Apple JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parsing Apple JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.KID == kid {
			return jwt.ParseRSAPublicKeyFromPEM(buildRSAPEM(key.N, key.E))
		}
	}

	return nil, fmt.Errorf("Apple key %s not found", kid)
}

func buildRSAPEM(n, e string) []byte {
	// In production, properly reconstruct RSA key from JWK components.
	// For now, we use a simplified approach — the actual JWKS parsing
	// should use a proper JWK library in production.
	return nil
}

// --- Google ---

type GoogleOAuth struct {
	clientID string
}

func NewGoogleOAuth(clientID string) *GoogleOAuth {
	return &GoogleOAuth{clientID: clientID}
}

func (g *GoogleOAuth) VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verifying Google token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google token verification failed: status %d", resp.StatusCode)
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
		return nil, fmt.Errorf("Google token audience mismatch: got %s, want %s", result.Aud, g.clientID)
	}

	if result.Sub == "" {
		return nil, fmt.Errorf("missing sub in Google token")
	}

	return &OAuthUserInfo{
		Provider:   "google",
		ProviderID: result.Sub,
		Email:      result.Email,
	}, nil
}
