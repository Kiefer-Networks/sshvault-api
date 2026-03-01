package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	TokenKindEmailVerify  = "email_verify"
	TokenKindPasswordReset = "password_reset"
)

type VerificationToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	Kind      string
	ExpiresAt time.Time
	Used      bool
	CreatedAt time.Time
}

type VerificationRepository interface {
	Create(ctx context.Context, token *VerificationToken) error
	GetByHash(ctx context.Context, tokenHash, kind string) (*VerificationToken, error)
	MarkUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, kind string) error
}
