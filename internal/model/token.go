package model

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	FamilyID       uuid.UUID  `json:"-"`
	ParentID       *uuid.UUID `json:"-"`
	ConsumedAt     *time.Time `json:"-"`
	SessionVersion int64      `json:"-"`
	ID             uuid.UUID  `json:"id"`
	UserID         uuid.UUID  `json:"user_id"`
	TokenHash      string     `json:"-"`
	DeviceName     string     `json:"device_name,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	Revoked        bool       `json:"-"`
}
