package coupon

import (
	"time"

	"github.com/google/uuid"
)

// Coupon represents a redeemable coupon code.
type Coupon struct {
	ID            uuid.UUID  `json:"id"`
	Code          string     `json:"code"`
	GrantSync     bool       `json:"grant_sync"`
	GrantTeleport bool       `json:"grant_teleport"`
	SyncDays      int        `json:"sync_days"`
	MaxUses       int        `json:"max_uses"`
	UsedCount     int        `json:"used_count"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	CreatedBy     string     `json:"created_by"`
}

// Redemption represents a user's coupon redemption.
type Redemption struct {
	ID         uuid.UUID `json:"id"`
	CouponID   uuid.UUID `json:"coupon_id"`
	UserID     uuid.UUID `json:"user_id"`
	RedeemedAt time.Time `json:"redeemed_at"`
}

// RedeemResult is returned to the client after a successful redemption.
type RedeemResult struct {
	SyncGranted     bool `json:"sync_granted"`
	TeleportGranted bool `json:"teleport_granted"`
	SyncDays        int  `json:"sync_days"`
}
