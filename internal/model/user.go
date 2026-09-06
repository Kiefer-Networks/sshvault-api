package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	SessionVersion int64      `json:"-"`
	ID             uuid.UUID  `json:"id"`
	Email          string     `json:"email"`
	Password       string     `json:"-"`
	Verified       bool       `json:"verified"`
	Avatar         string     `json:"avatar,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"-"`
}
