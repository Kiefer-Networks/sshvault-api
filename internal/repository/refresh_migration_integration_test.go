package repository

import (
	"context"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshMigrationPreservesLegacySessions(t *testing.T) {
	p := testutil.Database(t, 24)
	ctx := context.Background()
	testutil.Exec(t, p, `INSERT INTO users(email,password,verified,session_version) VALUES('legacy@example.com','unusable',TRUE,7)`)
	testutil.Exec(t, p, `INSERT INTO refresh_tokens(user_id,token_hash,expires_at) SELECT id,'legacy-token',NOW()+interval '1 hour' FROM users`)
	up, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "025_auth_replay_admission.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(up))
	repo := NewTokenRepository(p)
	token, err := repo.GetByHash(ctx, "legacy-token")
	if err != nil || token == nil {
		t.Fatalf("legacy token missing: %v", err)
	}
	if token.FamilyID != token.ID || token.ParentID != nil || token.ConsumedAt != nil || token.SessionVersion != 7 || token.Revoked {
		t.Fatalf("legacy token changed: %+v", token)
	}
	consumed, err := repo.ConsumeRefreshToken(ctx, "legacy-token")
	if err != nil || consumed == nil || consumed.ConsumedAt == nil {
		t.Fatalf("legacy token cannot rotate: %v", err)
	}
	down, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "025_auth_replay_admission.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, string(down)); err == nil {
		t.Fatal("unsafe downgrade allowed")
	}
	token, err = repo.GetByHash(ctx, "legacy-token")
	if err != nil || token.ConsumedAt == nil {
		t.Fatal("downgrade removed replay history")
	}
}
