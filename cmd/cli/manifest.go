package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

// ============================================================
// MANIFEST TYPES
// ============================================================

type restoreManifest struct {
	FormatVersion     int            `json:"format_version"`
	DumpSHA256        string         `json:"dump_sha256"`
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

func captureManifest(ctx context.Context, p repository.Querier) (*restoreManifest, error) {
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
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
	digest, err := hex.DecodeString(m.DumpSHA256)
	if m.FormatVersion != 1 || err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("manifest requires format version 1 and a SHA-256 dump digest")
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
	userIndex := make(map[uuid.UUID]int)
	for _, u := range append(append([]manifestUser{}, a.DeletedUsers...), b.DeletedUsers...) {
		if i, found := userIndex[u.ID]; found {
			if u.DeletedAt.After(merged.DeletedUsers[i].DeletedAt) {
				merged.DeletedUsers[i] = u
			}
		} else {
			userIndex[u.ID] = len(merged.DeletedUsers)
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
		if _, err := fmt.Fprintf(w, "UPDATE public.users SET deleted_at = GREATEST(deleted_at, '%s'::timestamptz), updated_at = now() WHERE id = '%s';\n", u.DeletedAt.UTC().Format(time.RFC3339Nano), u.ID.String()); err != nil {
			return err
		}
	}
	return nil
}
