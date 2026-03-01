package model

import (
	"time"

	"github.com/google/uuid"
)

type Vault struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Version   int       `json:"version"`
	Blob      []byte    `json:"blob,omitempty"`
	Checksum  string    `json:"checksum,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type VaultHistory struct {
	ID        uuid.UUID `json:"id"`
	VaultID   uuid.UUID `json:"vault_id"`
	Version   int       `json:"version"`
	Blob      []byte    `json:"blob,omitempty"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}
