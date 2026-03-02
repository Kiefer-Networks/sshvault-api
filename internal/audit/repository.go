package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository handles database operations for audit logs.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a new audit repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Insert writes an audit entry to the database.
func (r *Repository) Insert(ctx context.Context, e *Entry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	if e.Level == "" {
		e.Level = LevelInfo
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}

	detailsJSON, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("marshaling audit details: %w", err)
	}

	query := `
		INSERT INTO audit_logs (id, timestamp, level, category, action, actor_id, actor_email,
			resource_type, resource_id, ip_address, user_agent, request_id, details, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err = r.pool.Exec(ctx, query,
		e.ID, e.Timestamp, string(e.Level), string(e.Category), string(e.Action),
		e.ActorID, e.ActorEmail, e.ResourceType, e.ResourceID,
		e.IPAddress, e.UserAgent, e.RequestID, detailsJSON, e.DurationMS,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}
	return nil
}

// Query retrieves audit logs matching the given filter.
func (r *Repository) Query(ctx context.Context, f QueryFilter) (*QueryResult, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if f.ActorID != nil {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", argIdx))
		args = append(args, *f.ActorID)
		argIdx++
	}
	if f.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIdx))
		args = append(args, f.Category)
		argIdx++
	}
	if f.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, f.Action)
		argIdx++
	}
	if f.From != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *f.From)
		argIdx++
	}
	if f.To != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *f.To)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs %s", where)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting audit logs: %w", err)
	}

	// Clamp limit
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	// Fetch rows
	dataQuery := fmt.Sprintf(`
		SELECT id, timestamp, level, category, action, actor_id, actor_email,
			resource_type, resource_id, ip_address, user_agent, request_id, details, duration_ms
		FROM audit_logs %s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit logs: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var detailsJSON []byte
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.Level, &e.Category, &e.Action,
			&e.ActorID, &e.ActorEmail, &e.ResourceType, &e.ResourceID,
			&e.IPAddress, &e.UserAgent, &e.RequestID, &detailsJSON, &e.DurationMS,
		); err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &e.Details)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit rows: %w", err)
	}

	if entries == nil {
		entries = []Entry{}
	}

	return &QueryResult{
		Entries: entries,
		Total:   total,
		Limit:   f.Limit,
		Offset:  f.Offset,
	}, nil
}

// AnonymizeUser anonymizes PII for a given user using the database function.
func (r *Repository) AnonymizeUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var affected int
	err := r.pool.QueryRow(ctx, "SELECT audit_anonymize_user($1)", userID).Scan(&affected)
	if err != nil {
		return 0, fmt.Errorf("anonymizing audit logs for user %s: %w", userID, err)
	}
	return affected, nil
}

// PurgeOld removes audit logs older than the cutoff using the database function.
func (r *Repository) PurgeOld(ctx context.Context, cutoff time.Time) (int, error) {
	var affected int
	err := r.pool.QueryRow(ctx, "SELECT audit_purge_old($1)", cutoff).Scan(&affected)
	if err != nil {
		return 0, fmt.Errorf("purging old audit logs: %w", err)
	}
	return affected, nil
}
