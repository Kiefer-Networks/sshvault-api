package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
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
	if err := c.Register("https://appleid.apple.com/auth/keys", jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		log.Error().Err(err).Msg("failed to register Apple JWKS cache")
	}

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

	token, err := parser.Parse(idToken, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("apple key %s not found in JWKS", kid)
		}

		var rawKey any
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

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing or invalid sub in Apple token")
	}

	email, _ := claims["email"].(string)

	var emailVerified bool
	switch ev := claims["email_verified"].(type) {
	case bool:
		emailVerified = ev
	case string:
		emailVerified = ev == "true"
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
	cache    *jwk.Cache
}

func NewGoogleOAuth(clientID string) *GoogleOAuth {
	ctx := context.Background()
	c := jwk.NewCache(ctx)
	if err := c.Register("https://www.googleapis.com/oauth2/v3/certs", jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		log.Error().Err(err).Msg("failed to register Google JWKS cache")
	}

	return &GoogleOAuth{
		clientID: clientID,
		cache:    c,
	}
}

func (g *GoogleOAuth) VerifyToken(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	set, err := g.cache.Get(ctx, "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, fmt.Errorf("fetching Google JWKS: %w", err)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://accounts.google.com"),
		jwt.WithAudience(g.clientID),
	)

	token, err := parser.Parse(idToken, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("google key %s not found in JWKS", kid)
		}

		var rawKey any
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("extracting raw key: %w", err)
		}
		return rawKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("verifying Google ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid Google token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing or invalid sub in Google token")
	}

	email, _ := claims["email"].(string)

	var emailVerified bool
	switch ev := claims["email_verified"].(type) {
	case bool:
		emailVerified = ev
	case string:
		emailVerified = ev == "true"
	}

	if !emailVerified {
		return nil, fmt.Errorf("google email not verified")
	}

	return &OAuthUserInfo{
		Provider:   "google",
		ProviderID: sub,
		Email:      email,
	}, nil
}
