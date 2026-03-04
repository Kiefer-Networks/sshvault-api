package teleport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository persists Teleport cluster and session data.
type Repository interface {
	CreateCluster(ctx context.Context, c *Cluster) error
	GetCluster(ctx context.Context, id, userID uuid.UUID) (*Cluster, error)
	ListClusters(ctx context.Context, userID uuid.UUID) ([]Cluster, error)
	DeleteCluster(ctx context.Context, id, userID uuid.UUID) error
	UpdateCluster(ctx context.Context, c *Cluster) error

	SaveSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, clusterID, userID uuid.UUID) (*Session, error)
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	IsTeleportUnlocked(ctx context.Context, userID uuid.UUID) (bool, error)
	SetTeleportUnlocked(ctx context.Context, userID uuid.UUID, unlocked bool) error
}

type pgRepo struct {
	pool *pgxpool.Pool
}

// NewRepository creates a PostgreSQL-backed Teleport repository.
func NewRepository(pool *pgxpool.Pool) Repository {
	return &pgRepo{pool: pool}
}

func (r *pgRepo) CreateCluster(ctx context.Context, c *Cluster) error {
	now := time.Now()
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.CreatedAt = now
	c.UpdatedAt = now

	meta, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO teleport_clusters (id, user_id, name, proxy_addr, auth_method, identity, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.UserID, c.Name, c.ProxyAddr, c.AuthMethod, c.Identity, meta, c.CreatedAt, c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating teleport cluster: %w", err)
	}
	return nil
}

func (r *pgRepo) GetCluster(ctx context.Context, id, userID uuid.UUID) (*Cluster, error) {
	var c Cluster
	var meta []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, name, proxy_addr, auth_method, identity, metadata, created_at, updated_at
		FROM teleport_clusters WHERE id = $1 AND user_id = $2`, id, userID).
		Scan(&c.ID, &c.UserID, &c.Name, &c.ProxyAddr, &c.AuthMethod, &c.Identity, &meta, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting teleport cluster: %w", err)
	}
	if meta != nil {
		_ = json.Unmarshal(meta, &c.Metadata)
	}
	return &c, nil
}

func (r *pgRepo) ListClusters(ctx context.Context, userID uuid.UUID) ([]Cluster, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, name, proxy_addr, auth_method, metadata, created_at, updated_at
		FROM teleport_clusters WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing teleport clusters: %w", err)
	}
	defer rows.Close()

	var clusters []Cluster
	for rows.Next() {
		var c Cluster
		var meta []byte
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.ProxyAddr, &c.AuthMethod, &meta, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning teleport cluster: %w", err)
		}
		if meta != nil {
			_ = json.Unmarshal(meta, &c.Metadata)
		}
		clusters = append(clusters, c)
	}
	return clusters, rows.Err()
}

func (r *pgRepo) DeleteCluster(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM teleport_clusters WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("deleting teleport cluster: %w", err)
	}
	return nil
}

func (r *pgRepo) UpdateCluster(ctx context.Context, c *Cluster) error {
	c.UpdatedAt = time.Now()
	meta, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		UPDATE teleport_clusters
		SET name = $1, proxy_addr = $2, auth_method = $3, identity = $4, metadata = $5, updated_at = $6
		WHERE id = $7 AND user_id = $8`,
		c.Name, c.ProxyAddr, c.AuthMethod, c.Identity, meta, c.UpdatedAt, c.ID, c.UserID)
	if err != nil {
		return fmt.Errorf("updating teleport cluster: %w", err)
	}
	return nil
}

func (r *pgRepo) SaveSession(ctx context.Context, s *Session) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.CreatedAt = time.Now()

	// Upsert: replace existing session for the same cluster+user.
	_, err := r.pool.Exec(ctx, `
		INSERT INTO teleport_sessions (id, cluster_id, user_id, session_token, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET session_token = $4, expires_at = $5, created_at = $6`,
		s.ID, s.ClusterID, s.UserID, s.SessionToken, s.ExpiresAt, s.CreatedAt)
	if err != nil {
		return fmt.Errorf("saving teleport session: %w", err)
	}
	return nil
}

func (r *pgRepo) GetSession(ctx context.Context, clusterID, userID uuid.UUID) (*Session, error) {
	var s Session
	err := r.pool.QueryRow(ctx, `
		SELECT id, cluster_id, user_id, session_token, expires_at, created_at
		FROM teleport_sessions
		WHERE cluster_id = $1 AND user_id = $2 AND expires_at > NOW()
		ORDER BY created_at DESC LIMIT 1`, clusterID, userID).
		Scan(&s.ID, &s.ClusterID, &s.UserID, &s.SessionToken, &s.ExpiresAt, &s.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting teleport session: %w", err)
	}
	return &s, nil
}

func (r *pgRepo) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	result, err := r.pool.Exec(ctx, `DELETE FROM teleport_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("deleting expired teleport sessions: %w", err)
	}
	return result.RowsAffected(), nil
}

func (r *pgRepo) IsTeleportUnlocked(ctx context.Context, userID uuid.UUID) (bool, error) {
	var unlocked bool
	err := r.pool.QueryRow(ctx, `
		SELECT teleport_unlocked FROM users WHERE id = $1 AND deleted_at IS NULL`,
		userID).Scan(&unlocked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("checking teleport_unlocked: %w", err)
	}
	return unlocked, nil
}

func (r *pgRepo) SetTeleportUnlocked(ctx context.Context, userID uuid.UUID, unlocked bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET teleport_unlocked = $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL`, unlocked, userID)
	if err != nil {
		return fmt.Errorf("setting teleport_unlocked: %w", err)
	}
	return nil
}
