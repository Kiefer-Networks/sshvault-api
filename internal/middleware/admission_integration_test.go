package middleware

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
	"sync"
	"testing"
)

func TestLoginSuccessPreservesPendingAndNewerAttempts(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	g := NewBruteForceGuard(p)
	reserve := func() uuid.UUID {
		t.Helper()
		id, _, err := g.ReserveAttempt(ctx, " USER@example.com ", "192.0.2.1")
		if err != nil || id == uuid.Nil {
			t.Fatalf("reserve: %v", err)
		}
		return id
	}
	complete := func(id uuid.UUID, success bool) {
		t.Helper()
		if err := g.CompleteAttempt(ctx, "user@example.com", id, success); err != nil {
			t.Fatal(err)
		}
	}
	old := reserve()
	complete(old, false)
	pending := reserve()
	success := reserve()
	newer := reserve()
	complete(newer, false)
	complete(success, true)
	complete(pending, false)
	reserve()
	reserve()
	reserve()
	if id, _, err := g.ReserveAttempt(ctx, "user@example.com", "192.0.2.1"); err != nil || id != uuid.Nil {
		t.Fatalf("success released pending/newer charge: %v %v", id, err)
	}
	testutil.Exec(t, p, `UPDATE login_attempts SET created_at=NOW()-interval '16 minutes'`)
	reserve()
}

func TestLoginIPAdmissionIsAtomicAcrossAccounts(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	g := NewBruteForceGuard(p)
	results := make(chan uuid.UUID, 24)
	failures := make(chan error, 24)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id, _, err := g.ReserveAttempt(ctx, fmt.Sprintf("user%d@example.com", i), "192.0.2.1")
			results <- id
			failures <- err
		}(i)
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
	count := 0
	for id := range results {
		if id != uuid.Nil {
			count++
		}
	}
	if count != IPBlockThreshold {
		t.Fatalf("IP admissions=%d", count)
	}
}
