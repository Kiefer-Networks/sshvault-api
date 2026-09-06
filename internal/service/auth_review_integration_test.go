package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type reviewMailbox struct {
	mu     sync.Mutex
	tokens []string
}

func (m *reviewMailbox) SendVerificationEmail(_ context.Context, _, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = append(m.tokens, token)
	return nil
}
func (m *reviewMailbox) SendPasswordResetEmail(context.Context, string, string) error { return nil }
func (m *reviewMailbox) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tokens) == 0 {
		return ""
	}
	return m.tokens[len(m.tokens)-1]
}
func (m *reviewMailbox) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.tokens) }
func TestRegistrationConcurrentResendsHaveOneRecipientBudget(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	mail := &reviewMailbox{}
	svc := NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), mail, nil)
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "budget@example.com", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Register(ctx, &RegisterRequest{Email: " BUDGET@example.com ", Password: "password123"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := mail.count(); got != 1 {
		t.Errorf("recipient received %d mails within cooldown", got)
	}
	var active int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM verification_tokens WHERE NOT used").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Errorf("%d outstanding verification links", active)
	}
}
func TestLaterSignupSurvivesDelayedEarlierIssuance(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	mail := &reviewMailbox{}
	created, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	earlier := NewAuthService(afterCreateUsers{users, func(_ *model.User) { close(created); <-release }}, tokens, verify, tx, newTestJWT(t), mail, nil)
	later := NewAuthService(users, tokens, verify, tx, newTestJWT(t), mail, nil)
	done := make(chan error, 1)
	go func() {
		_, err := earlier.Register(ctx, &RegisterRequest{Email: "victim@example.com", Password: "attacker-password"})
		done <- err
	}()
	<-created
	if _, err := later.Register(ctx, &RegisterRequest{Email: "victim@example.com", Password: "victim-password"}); err != nil {
		t.Fatal(err)
	}
	victimToken := mail.last()
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := later.VerifyEmail(ctx, victimToken, "victim-password"); err != nil {
		t.Fatalf("delayed earlier request invalidated victim token: %v", err)
	}
	if _, err := later.Login(ctx, &LoginRequest{Email: "victim@example.com", Password: "victim-password"}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordResetInvalidatesObsoleteActivationToken(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mail := &reviewMailbox{}
	svc := NewAuthService(users, repository.NewTokenRepository(p), verify, repository.NewTransactor(p), newTestJWT(t), mail, nil)
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "victim@example.com", Password: "attacker-password"}); err != nil {
		t.Fatal(err)
	}
	signupToken := mail.last()
	u, err := users.GetByEmail(ctx, "victim@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("owner-reset"), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err = svc.ResetPassword(ctx, "owner-reset", "owner-password"); err != nil {
		t.Fatal(err)
	}
	if err = svc.VerifyEmail(ctx, signupToken, "password123"); err == nil {
		t.Fatal("signup token remained usable after account recovery")
	}
}

func TestFirstDeliveredActivationTokenLetsMailboxOwnerChoosePassword(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mail := &reviewMailbox{}
	svc := NewAuthService(users, repository.NewTokenRepository(p), verify, repository.NewTransactor(p), newTestJWT(t), mail, nil)
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "owner@example.com", Password: "attacker-password"}); err != nil {
		t.Fatal(err)
	}
	first := mail.last()
	if result, err := svc.Login(ctx, &LoginRequest{Email: "owner@example.com", Password: "attacker-password"}); err == nil || result != nil {
		t.Fatal("requester's password worked before mailbox activation")
	}
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "owner@example.com", Password: "another-requester-password"}); err != nil {
		t.Fatal(err)
	}
	if mail.count() != 1 {
		t.Fatal("cooldown sent another message")
	}
	if err := svc.VerifyEmail(ctx, first, "owner-chosen-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, &LoginRequest{Email: "owner@example.com", Password: "owner-chosen-password"}); err != nil {
		t.Fatalf("mailbox owner's chosen password failed: %v", err)
	}
	for _, password := range []string{"attacker-password", "another-requester-password"} {
		if result, err := svc.Login(ctx, &LoginRequest{Email: "owner@example.com", Password: password}); err == nil || result != nil {
			t.Fatal("requester's password authorized activated account")
		}
	}
}

func TestAdmittedRegistrationReplacesOldActivationLink(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mail := &reviewMailbox{}
	svc := NewAuthService(users, repository.NewTokenRepository(p), verify, repository.NewTransactor(p), newTestJWT(t), mail, nil)
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "owner@example.com", Password: "requester-password"}); err != nil {
		t.Fatal(err)
	}
	first := mail.last()
	if _, err := p.Exec(ctx, "UPDATE mail_send_budgets SET next_send_at=NOW()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "owner@example.com", Password: "requester-password"}); err != nil {
		t.Fatal(err)
	}
	if mail.count() != 2 || first == mail.last() {
		t.Fatal("admitted resend did not replace link")
	}
	if err := svc.VerifyEmail(ctx, first, "owner-password"); err == nil {
		t.Fatal("superseded link activated account")
	}
	if err := svc.VerifyEmail(ctx, mail.last(), "owner-password"); err != nil {
		t.Fatal(err)
	}
}
