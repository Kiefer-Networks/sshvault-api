package model

import (
	"time"

	"github.com/google/uuid"
)

type Device struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	Name      string     `json:"name"`
	Platform  string     `json:"platform"`
	LastSync  *time.Time `json:"last_sync,omitempty"`
	LastIP    string     `json:"last_ip,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
