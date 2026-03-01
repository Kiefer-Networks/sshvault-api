package model

import (
	"time"

	"github.com/google/uuid"
)

type Subscription struct {
	ID                 uuid.UUID  `json:"id"`
	UserID             uuid.UUID  `json:"user_id"`
	Provider           string     `json:"provider"`
	ProviderSubID      string     `json:"provider_sub_id"`
	ProviderCustomerID string     `json:"provider_customer_id"`
	Status             string     `json:"status"`
	CurrentPeriodStart *time.Time `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

const (
	SubStatusActive   = "active"
	SubStatusCanceled = "canceled"
	SubStatusExpired  = "expired"
	SubStatusPastDue  = "past_due"
)
