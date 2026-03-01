package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type pgDeviceRepo struct {
	pool *pgxpool.Pool
}

func NewDeviceRepository(pool *pgxpool.Pool) DeviceRepository {
	return &pgDeviceRepo{pool: pool}
}

func (r *pgDeviceRepo) Create(ctx context.Context, device *model.Device) error {
	query := `
		INSERT INTO devices (id, user_id, name, platform, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}
	device.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		device.ID, device.UserID, device.Name, device.Platform, device.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating device: %w", err)
	}
	return nil
}

func (r *pgDeviceRepo) GetByUserID(ctx context.Context, userID uuid.UUID) ([]model.Device, error) {
	query := `
		SELECT id, user_id, name, platform, last_sync, created_at
		FROM devices WHERE user_id = $1 ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("getting devices: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		var d model.Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.LastSync, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (r *pgDeviceRepo) Delete(ctx context.Context, id, userID uuid.UUID) error {
	query := `DELETE FROM devices WHERE id = $1 AND user_id = $2`
	_, err := r.pool.Exec(ctx, query, id, userID)
	if err != nil {
		return fmt.Errorf("deleting device: %w", err)
	}
	return nil
}

func (r *pgDeviceRepo) UpdateLastSync(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE devices SET last_sync = $1 WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("updating last sync: %w", err)
	}
	return nil
}
