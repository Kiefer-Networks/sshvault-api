package repository

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestVerificationMigrationDownCannotLoseProvenance(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	testutil.Exec(t, p, "INSERT INTO users(email,password) VALUES('post-upgrade@example.com','unusable')")
	down, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "023_verification_lifecycle.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, string(down)); err == nil {
		t.Fatal("down migration allowed unverified post-upgrade account to lose provenance")
	}
	var grandfathered bool
	if err = p.QueryRow(ctx, "SELECT verification_grandfathered FROM users WHERE email='post-upgrade@example.com'").Scan(&grandfathered); err != nil {
		t.Fatal(err)
	}
	if grandfathered {
		t.Fatal("blocked downgrade altered account provenance")
	}
	testutil.Exec(t, p, "UPDATE users SET verified=TRUE")
	testutil.Exec(t, p, string(down))
	up, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "023_verification_lifecycle.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(up))
	testutil.Exec(t, p, "INSERT INTO users(email,password) VALUES('after-reupgrade@example.com','unusable')")
	if err = p.QueryRow(ctx, "SELECT verification_grandfathered FROM users WHERE email='after-reupgrade@example.com'").Scan(&grandfathered); err != nil {
		t.Fatal(err)
	}
	if grandfathered {
		t.Fatal("re-upgrade grandfathered a newly inserted account")
	}
}

func TestRecipientMailBudgetIsAtomicAcrossConcurrentCallers(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	digest := auth.HashToken("mail-recipient:shared@example.com")
	start := make(chan struct{})
	results := make(chan bool, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			admitted, err := NewVerificationRepository(p).ReserveMailSend(ctx, digest, TokenKindEmailChange)
			results <- admitted
			failures <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	admitted := 0
	for allowed := range results {
		if allowed {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("concurrent recipient send admissions=%d", admitted)
	}
	verify := NewVerificationRepository(p)
	if allowed, err := verify.ReserveMailSend(ctx, digest, TokenKindEmailChange); err != nil || allowed {
		t.Fatalf("cooldown bypass: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := verify.ReserveMailSend(ctx, digest, TokenKindPasswordReset); err != nil || !allowed {
		t.Fatalf("different purpose incorrectly suppressed: %v", err)
	}
	testutil.Exec(t, p, "UPDATE mail_send_budgets SET next_send_at=NOW()-interval '1 second'")
	if allowed, err := verify.ReserveMailSend(ctx, digest, TokenKindEmailChange); err != nil || !allowed {
		t.Fatalf("expired budget not renewed: %v", err)
	}
}

func TestActivationMigrationRemovesDraftCredentialBinding(t *testing.T) {
	p := testutil.Database(t, 23)
	ctx := context.Background()
	// Simulate the earlier unpublished migration draft on an already-upgraded database.
	testutil.Exec(t, p, "ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS registration_password_hash TEXT NOT NULL DEFAULT ''")
	testutil.Exec(t, p, "INSERT INTO users(email,password) VALUES('pending@example.com','!unverified:random')")
	testutil.Exec(t, p, "INSERT INTO verification_tokens(user_id,token_hash,kind,expires_at,registration_password_hash) SELECT id,'live-token','email_verify',NOW()+interval '1 hour','obsolete-requester-hash' FROM users")
	up, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "024_mailbox_owner_activation.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(up))
	var count int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='verification_tokens' AND column_name='registration_password_hash'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("obsolete credential column remains: count=%d err=%v", count, err)
	}
	token, err := NewVerificationRepository(p).GetByHash(ctx, "live-token", TokenKindEmailVerify)
	if err != nil || token == nil {
		t.Fatal("cleanup invalidated the mailbox owner's live link")
	}
	down, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "024_mailbox_owner_activation.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(down))
	testutil.Exec(t, p, string(up))
	var verified, grandfathered bool
	if err = p.QueryRow(ctx, "SELECT verified,verification_grandfathered FROM users").Scan(&verified, &grandfathered); err != nil || verified || grandfathered {
		t.Fatal("cleanup down/up changed pending account provenance")
	}
}
