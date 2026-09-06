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
