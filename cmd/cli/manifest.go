package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ============================================================
// MANIFEST TYPES
// ============================================================

type restoreManifest struct {
	CreatedAt         time.Time      `json:"created_at"`
	DeletedUsers      []manifestUser `json:"deleted_users"`
	RevokedTokenCount int            `json:"revoked_token_count"`
}

type manifestUser struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	DeletedAt time.Time `json:"deleted_at"`
}

// ============================================================
// MANIFEST HELPERS
// ============================================================

func captureManifest(ctx context.Context, p *pgxpool.Pool) (*restoreManifest, error) {
	m := &restoreManifest{CreatedAt: time.Now()}

	// Deleted users
	rows, err := p.Query(ctx,
		`SELECT id, email, deleted_at FROM users WHERE deleted_at IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("querying deleted users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u manifestUser
		if err := rows.Scan(&u.ID, &u.Email, &u.DeletedAt); err != nil {
			return nil, fmt.Errorf("scanning deleted user: %w", err)
		}
		m.DeletedUsers = append(m.DeletedUsers, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating deleted users: %w", err)
	}

	// Revoked token count
	err = p.QueryRow(ctx,
		`SELECT COUNT(*) FROM refresh_tokens WHERE revoked = TRUE`).Scan(&m.RevokedTokenCount)
	if err != nil {
		return nil, fmt.Errorf("counting revoked tokens: %w", err)
	}

	return m, nil
}

func writeManifestFile(m *restoreManifest, path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	return nil
}

func loadManifestFile(path string) (*restoreManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var m restoreManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}

func mergeManifests(a, b *restoreManifest) *restoreManifest {
	merged := &restoreManifest{CreatedAt: time.Now()}

	// Union of deleted users (deduplicate by ID)
	userSeen := make(map[uuid.UUID]bool)
	for _, u := range a.DeletedUsers {
		merged.DeletedUsers = append(merged.DeletedUsers, u)
		userSeen[u.ID] = true
	}
	for _, u := range b.DeletedUsers {
		if !userSeen[u.ID] {
			merged.DeletedUsers = append(merged.DeletedUsers, u)
		}
	}

	// Take the higher revoked token count
	merged.RevokedTokenCount = a.RevokedTokenCount
	if b.RevokedTokenCount > merged.RevokedTokenCount {
		merged.RevokedTokenCount = b.RevokedTokenCount
	}

	return merged
}

func applyManifest(ctx context.Context, p *pgxpool.Pool, m *restoreManifest) (deletedUsers, revokedTokens int) {
	// Re-delete users that were deleted before the restore
	for _, u := range m.DeletedUsers {
		result, err := p.Exec(ctx,
			`UPDATE users SET deleted_at = $1, updated_at = now()
			 WHERE id = $2 AND deleted_at IS NULL`, u.DeletedAt, u.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to re-delete user %s: %v\n", u.Email, err)
			continue
		}
		if result.RowsAffected() > 0 {
			deletedUsers++
			// Also revoke tokens for re-deleted users
			if _, err := p.Exec(ctx,
				`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`,
				u.ID); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: failed to revoke tokens for %s: %v\n", u.Email, err)
			}
		}
	}

	// Re-revoke tokens for all deleted users (catch-all)
	result, err := p.Exec(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE
		 WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL)
		   AND revoked = FALSE`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: failed to re-revoke tokens: %v\n", err)
	} else {
		revokedTokens = int(result.RowsAffected())
	}

	return
}
