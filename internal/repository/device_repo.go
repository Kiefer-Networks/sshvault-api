package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type DeviceRepository interface {
	Create(ctx context.Context, device *model.Device) error
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]model.Device, error)
	Delete(ctx context.Context, id, userID uuid.UUID) error
	UpdateLastSync(ctx context.Context, id, userID uuid.UUID) error
}
