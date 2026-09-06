package repository

import (
	"context"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
	"runtime"
	"testing"
	"time"
)

func TestRefreshCleanupRetainsFamilyDuringRotation(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uid := uuid.New()
	testutil.Exec(t, p, `INSERT INTO users(id,email,password,verified) VALUES($1,'cleanup@example.com','unusable',TRUE)`, uid)
	repo := NewTokenRepository(p)
	original := &model.RefreshToken{UserID: uid, TokenHash: "original", ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Create(ctx, original); err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, uid); err != nil {
		t.Fatal(err)
	}
	// The transaction began before expiration. It may finish after wall-clock
	// expiry; PostgreSQL NOW() still allows its already-started rotation.
	testutil.Exec(t, p, `UPDATE refresh_tokens SET expires_at=clock_timestamp() WHERE id=$1`, original.ID)
	txCtx := context.WithValue(ctx, ctxTxKey{}, tx)
	consumed, err := repo.ConsumeRefreshToken(txCtx, original.TokenHash)
	if err != nil || consumed == nil {
		t.Fatalf("rotation admission: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := repo.DeleteExpired(ctx); done <- err }()
	for {
		select {
		case err := <-done:
			t.Fatalf("cleanup did not serialize with rotation: %v", err)
		default:
		}
		var waiting bool
		if err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND pid<>pg_backend_pid() AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		runtime.Gosched()
	}
	successor := &model.RefreshToken{UserID: uid, TokenHash: "successor", FamilyID: original.FamilyID, ParentID: &original.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err = repo.Create(txCtx, successor); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	token, err := repo.GetByHash(ctx, original.TokenHash)
	if err != nil || token == nil {
		t.Fatalf("cleanup removed in-flight rotation ancestry: %v", err)
	}
	testutil.Exec(t, p, `UPDATE refresh_tokens SET expires_at=NOW()-interval '1 second'`)
	count, err := repo.DeleteExpired(ctx)
	if err != nil || count != 2 {
		t.Fatalf("expired family cleanup count=%d err=%v", count, err)
	}
}
