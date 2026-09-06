package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type Claims struct {
	SessionVersion int64 `json:"session_version"`
	jwt.RegisteredClaims
}

// UnmarshalJSON distinguishes required zero-valued claims from absent/null claims.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type wireClaims Claims
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, key := range []string{"exp", "iat", "session_version"} {
		raw, ok := fields[key]
		if !ok || string(raw) == "null" || len(raw) == 0 || raw[0] == '"' {
			return fmt.Errorf("missing or invalid %s claim", key)
		}
	}
	var decoded wireClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = Claims(decoded)
	return nil
}

// Validate supplements the registered-claim validator with our session contract.
func (c *Claims) Validate() error {
	subject, err := uuid.Parse(c.Subject)
	if err != nil || subject == uuid.Nil {
		return fmt.Errorf("invalid subject")
	}
	if c.IssuedAt == nil || c.ExpiresAt == nil || !c.ExpiresAt.After(c.IssuedAt.Time) {
		return fmt.Errorf("invalid token lifetime")
	}
	if c.SessionVersion < 0 {
		return fmt.Errorf("invalid session version")
	}
	return nil
}
func NewJWTManager(privateKey ed25519.PrivateKey, accessTTL, refreshTTL time.Duration) *JWTManager {
	return &JWTManager{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (m *JWTManager) GenerateTokenPair(userID uuid.UUID, sessionVersion int64) (*TokenPair, string, error) {
	now := time.Now()
	accessExp := now.Add(m.accessTTL)

	accessClaims := &Claims{
		SessionVersion: sessionVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Issuer:    "sshvault",
			Audience:  jwt.ClaimStrings{"sshvault-api"},
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	accessStr, err := accessToken.SignedString(m.privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("signing access token: %w", err)
	}

	refreshRaw := uuid.New().String()
	refreshHash := HashToken(refreshRaw)

	return &TokenPair{
		AccessToken:  accessStr,
		RefreshToken: refreshRaw,
		ExpiresAt:    accessExp.Unix(),
	}, refreshHash, nil
}

func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	}, jwt.WithAudience("sshvault-api"), jwt.WithIssuer("sshvault"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (m *JWTManager) RefreshTTL() time.Duration {
	return m.refreshTTL
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
