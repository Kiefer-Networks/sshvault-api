package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
	if m.CreatedAt.IsZero() || m.RevokedTokenCount < 0 {
		return nil, fmt.Errorf("invalid manifest metadata")
	}
	for _, u := range m.DeletedUsers {
		if u.ID == uuid.Nil || u.DeletedAt.IsZero() {
			return nil, fmt.Errorf("invalid deleted user in manifest")
		}
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

// Values are rendered exclusively from typed UUIDs and times, never email/input SQL.
func appendManifestSQL(w io.Writer, m *restoreManifest) error {
	// Fresh generation prevents access JWTs from an older database state becoming valid.
	version, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return fmt.Errorf("generating session version: %w", err)
	}
	version.Add(version, big.NewInt(1))
	if _, err := fmt.Fprintf(w, "\nALTER TABLE public.users ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 0;\nUPDATE public.users SET session_version = %s;\n", version.String()); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "\nUPDATE public.refresh_tokens SET revoked = TRUE WHERE revoked = FALSE;\nUPDATE public.verification_tokens SET used = TRUE WHERE used = FALSE;"); err != nil {
		return err
	}
	for _, u := range m.DeletedUsers {
		if _, err := fmt.Fprintf(w, "UPDATE public.users SET deleted_at = '%s', updated_at = now() WHERE id = '%s' AND deleted_at IS NULL;\n", u.DeletedAt.UTC().Format(time.RFC3339Nano), u.ID.String()); err != nil {
			return err
		}
	}
	return nil
}
