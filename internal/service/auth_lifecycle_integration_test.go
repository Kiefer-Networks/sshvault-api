package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestLifecycleRegistrationOpaque(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	svc := NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), nil, nil)
	first, err := svc.Register(ctx, &RegisterRequest{Email: "new@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Register(ctx, &RegisterRequest{Email: "new@example.com", Password: "password123"})
	if err != nil {
		t.Errorf("existing account differs: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Errorf("new/existing responses differ: %s / %s", a, b)
	}
	var body map[string]any
	_ = json.Unmarshal(a, &body)
	for _, key := range []string{"user", "id", "access_token", "refresh_token"} {
		if _, ok := body[key]; ok {
			t.Errorf("registration exposes %s", key)
		}
	}
	var count int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM refresh_tokens").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("registration issued %d credentials", count)
	}
}
func TestLifecycleUnverifiedLoginAndProtectedAccess(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	jwt := newTestJWT(t)
	hash, err := auth.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{Email: "unverified@example.com", Password: hash}
	if err = users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), jwt, nil, nil)
	if res, err := svc.Login(ctx, &LoginRequest{Email: u.Email, Password: "password123"}); err == nil || res != nil {
		t.Error("unverified account received credentials")
	}
	pair, _, _ := jwt.GenerateTokenPair(u.ID, 0)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	middleware.NewAuthMiddleware(jwt, users).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, req)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "verification_required") {
		t.Errorf("protected access: %d %s", w.Code, w.Body)
	}
}
func TestLifecycleBearerCannotChangeEmail(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := NewUserService(users, repository.NewTokenRepository(p), repository.NewTransactor(p), repository.NewVerificationRepository(p), &mockMailer{})
	if _, err := svc.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "attacker@example.com"}); err == nil {
		t.Error("bearer-only email takeover accepted")
	}
	current, _ := users.GetByID(ctx, u.ID)
	if current.Email != u.Email {
		t.Errorf("active recovery address changed: %s", current.Email)
	}
}
func TestLifecyclePasswordReauthKeepsRecoveryAddress(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := NewUserService(users, repository.NewTokenRepository(p), repository.NewTransactor(p), repository.NewVerificationRepository(p), &mockMailer{})
	res, err := svc.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Email != "old@example.com" || !res.Verified || res.PendingEmail != "new@example.com" {
		t.Errorf("email must stay active and verified while confirmation is pending: %+v", res)
	}
	current, _ := users.GetByID(ctx, u.ID)
	if current.Email != "old@example.com" || current.PendingEmail != "new@example.com" {
		t.Errorf("pending state not persisted: %+v", current)
	}
}

type lifecycleMailbox struct{ verification, change, destination, resetDestination, resetToken string }

func (m *lifecycleMailbox) SendVerificationEmail(_ context.Context, _ string, token string) error {
	m.verification = token
	return nil
}
func (m *lifecycleMailbox) SendPasswordResetEmail(_ context.Context, email, token string) error {
	m.resetDestination = email
	m.resetToken = token
	return nil
}
func (m *lifecycleMailbox) SendEmailChangeEmail(_ context.Context, email, token string) error {
	m.change = token
	m.destination = email
	return nil
}

func TestLifecycleConfirmationAtomicAndSingleUse(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	jwt := newTestJWT(t)
	mail := &lifecycleMailbox{}
	as := NewAuthService(users, tokens, verify, tx, jwt, mail, nil)
	us := NewUserService(users, tokens, tx, verify, mail)
	response, err := registerVerified(t, as, ctx, &RegisterRequest{Email: "old@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	mail.verification = "obsolete-verification"
	if err = verify.Create(ctx, &repository.VerificationToken{UserID: response.User.ID, TokenHash: auth.HashToken(mail.verification), Kind: repository.TokenKindEmailVerify, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err = us.UpdateProfile(ctx, response.User.ID, &UpdateProfileRequest{Email: " NEW@example.com ", CurrentPassword: "password123"}); err != nil {
		t.Fatal(err)
	}
	if mail.destination != "new@example.com" || mail.change == "" {
		t.Fatal("confirmation not sent to pending mailbox")
	}
	if err = as.VerifyEmail(ctx, mail.change, "password123"); err == nil {
		t.Fatal("email-change token accepted for registration verification")
	}
	confirmer := us
	if err = confirmer.ConfirmEmailChange(ctx, mail.verification); err == nil {
		t.Fatal("registration token accepted as email change")
	}
	if err = as.ForgotPassword(ctx, "old@example.com"); err != nil {
		t.Fatal(err)
	}
	if mail.resetDestination != "old@example.com" {
		t.Fatal("pending address replaced active recovery mailbox")
	}
	if err = as.ForgotPassword(ctx, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	if mail.resetDestination != "old@example.com" {
		t.Fatal("pending mailbox received recovery token")
	}
	if err = confirmer.ConfirmEmailChange(ctx, mail.change); err != nil {
		t.Fatal(err)
	}
	if err = as.ResetPassword(ctx, mail.resetToken, "changed-password"); err == nil {
		t.Fatal("old mailbox reset token survived confirmation")
	}
	current, _ := users.GetByID(ctx, response.User.ID)
	if current.Email != "new@example.com" || current.PendingEmail != "" || !current.Verified || current.SessionVersion != 1 {
		t.Fatalf("confirmation state: %+v", current)
	}
	if err = confirmer.ConfirmEmailChange(ctx, mail.change); err == nil {
		t.Fatal("confirmation replay accepted")
	}
	if err = as.VerifyEmail(ctx, mail.verification, "password123"); err == nil {
		t.Fatal("obsolete verification token accepted")
	}
	if _, err = as.Refresh(ctx, &RefreshRequest{RefreshToken: response.RefreshToken}); err == nil {
		t.Fatal("old refresh remains usable")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	w := httptest.NewRecorder()
	middleware.NewAuthMiddleware(jwt, users).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("old access remains usable")
	}
	if _, err = as.Login(ctx, &LoginRequest{Email: "new@example.com", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleGrandfatheringUpgrade(t *testing.T) {
	p := testutil.Database(t, 22)
	ctx := context.Background()
	id := uuid.New()
	hash, _ := auth.HashPassword("password123")
	testutil.Exec(t, p, `INSERT INTO users(id,email,password,verified) VALUES($1,'legacy@example.com',$2,FALSE)`, id, hash)
	migration, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "023_verification_lifecycle.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(migration))
	users := repository.NewUserRepository(p)
	u, err := users.GetByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.Verified || !u.VerificationGrandfathered {
		t.Fatalf("upgrade lost explicit legacy status: %+v", u)
	}
	for _, name := range []string{
		"024_mailbox_owner_activation.up.sql",
		"025_auth_replay_admission.up.sql",
	} {
		migration, err = os.ReadFile(filepath.Join(testutil.MigrationDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		testutil.Exec(t, p, string(migration))
	}
	jwt := newTestJWT(t)
	tokens := repository.NewTokenRepository(p)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(p), repository.NewTransactor(p), jwt, nil, nil)
	pair, _, _ := jwt.GenerateTokenPair(id, 0)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	middleware.NewAuthMiddleware(jwt, users).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("legacy access denied: %d", w.Code)
	}
	login, err := svc.Login(ctx, &LoginRequest{Email: u.Email, Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	fresh := &model.User{Email: "new@example.com", Password: hash}
	if err = users.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	fresh, _ = users.GetByID(ctx, fresh.ID)
	if fresh.VerificationGrandfathered {
		t.Fatal("post-upgrade account grandfathered")
	}
}
func TestLifecycleConfirmationRollbackAndRetry(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	mail := &lifecycleMailbox{}
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	us := NewUserService(users, failRevokeTokens{tokens}, tx, verify, mail)
	if _, err := us.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err != nil {
		t.Fatal(err)
	}
	if err := us.ConfirmEmailChange(ctx, mail.change); err == nil {
		t.Fatal("injected revocation failure ignored")
	}
	current, _ := users.GetByID(ctx, u.ID)
	if current.Email != "old@example.com" || current.SessionVersion != 0 || current.PendingEmail != "new@example.com" {
		t.Fatal("failed confirmation partially committed")
	}
	stored, err := verify.GetByHash(ctx, auth.HashToken(mail.change), repository.TokenKindEmailChange)
	if err != nil || stored == nil {
		t.Fatal("failed confirmation consumed token")
	}
	us.tokenRepo = tokens
	if err = us.ConfirmEmailChange(ctx, mail.change); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
}
func TestLifecyclePendingTokenReplacementExpiryAndConflict(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	mail := &lifecycleMailbox{}
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	us := NewUserService(users, tokens, tx, verify, mail)
	request := func(email string) string {
		t.Helper()
		testutil.Exec(t, p, "UPDATE mail_send_budgets SET next_send_at=NOW()-interval '1 second'")
		if _, err := us.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: email, CurrentPassword: "password123"}); err != nil {
			t.Fatal(err)
		}
		return mail.change
	}
	old := request("first@example.com")
	current := request("second@example.com")
	if err := us.ConfirmEmailChange(ctx, old); err == nil {
		t.Fatal("superseded token accepted")
	}
	testutil.Exec(t, p, "UPDATE verification_tokens SET expires_at=NOW()-interval '1 second' WHERE token_hash=$1", auth.HashToken(current))
	if err := us.ConfirmEmailChange(ctx, current); err == nil {
		t.Fatal("expired token accepted")
	}
	current = request("second@example.com")
	other := &model.User{Email: "second@example.com", Password: hash}
	if err := users.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := us.ConfirmEmailChange(ctx, current); err == nil {
		t.Fatal("duplicate mailbox accepted")
	}
	got, _ := users.GetByID(ctx, u.ID)
	if got.Email != "old@example.com" || got.SessionVersion != 0 {
		t.Fatal("conflict partially installed mailbox")
	}
	stored, _ := verify.GetByHash(ctx, auth.HashToken(current), repository.TokenKindEmailChange)
	if stored == nil {
		t.Fatal("conflict consumed token")
	}
}
func TestLifecycleConcurrentConfirmationSingleWinner(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	tokens := repository.NewTokenRepository(p)
	tx := repository.NewTransactor(p)
	u := &model.User{Email: "old@example.com", Password: "hash", Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := users.SetPendingEmail(ctx, u.ID, "new@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("change"), Kind: repository.TokenKindEmailChange, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	readers.Add(2)
	us := NewUserService(users, tokens, tx, simultaneousVerificationReads{verify, &readers}, &lifecycleMailbox{})
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- us.ConfirmEmailChange(ctx, "change") }()
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("confirmation winners %d", success)
	}
	got, _ := users.GetByID(ctx, u.ID)
	if got.SessionVersion != 1 {
		t.Fatalf("version advanced %d times", got.SessionVersion)
	}
}
func TestLifecycleStalePasswordReauthCannotStartChange(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	wrapped := staleReadUsers{users, func() {
		testutil.Exec(t, p, "UPDATE users SET password='changed',session_version=session_version+1 WHERE id=$1", u.ID)
	}}
	svc := NewUserService(wrapped, repository.NewTokenRepository(p), repository.NewTransactor(p), repository.NewVerificationRepository(p), &lifecycleMailbox{})
	if _, err := svc.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err == nil {
		t.Fatal("stale password verification accepted")
	}
	got, _ := users.GetByID(ctx, u.ID)
	if got.PendingEmail != "" || got.Email != "old@example.com" {
		t.Fatal("stale request changed email")
	}
}

type failedVerificationCreate struct {
	repository.VerificationRepository
}

func (failedVerificationCreate) Create(context.Context, *repository.VerificationToken) error {
	return errors.New("injected token write failure")
}
func TestLifecyclePendingIssuanceRollback(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	mail := &lifecycleMailbox{}
	svc := NewUserService(users, repository.NewTokenRepository(p), repository.NewTransactor(p), failedVerificationCreate{verify}, mail)
	if _, err := svc.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err == nil {
		t.Fatal("injected write failure ignored")
	}
	got, _ := users.GetByID(ctx, u.ID)
	if got.PendingEmail != "" || mail.change != "" {
		t.Fatal("failed issuance installed pending state or delivered a token")
	}
}
func TestLifecycleVerifiedRegistrationPreservesPassword(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	mail := &lifecycleMailbox{}
	svc := NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), mail, nil)
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "new@example.com", Password: "original-password"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyEmail(ctx, mail.verification, "original-password"); err != nil {
		t.Fatal(err)
	}
	mail.verification = ""
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "new@example.com", Password: "attacker-password"}); err != nil {
		t.Fatal(err)
	}
	if mail.verification != "" {
		t.Fatal("verified account received a new signup link")
	}
	if _, err := svc.Login(ctx, &LoginRequest{Email: "new@example.com", Password: "original-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, &LoginRequest{Email: "new@example.com", Password: "attacker-password"}); err == nil {
		t.Fatal("registration overwrote existing credentials")
	}
}
func TestLifecyclePasswordChangeInvalidatesPendingConfirmation(t *testing.T) {
	for _, action := range []string{"change", "reset"} {
		t.Run(action, func(t *testing.T) {
			p := authDatabase(t)
			ctx := context.Background()
			users := repository.NewUserRepository(p)
			verify := repository.NewVerificationRepository(p)
			tokens := repository.NewTokenRepository(p)
			tx := repository.NewTransactor(p)
			mail := &lifecycleMailbox{}
			hash, _ := auth.HashPassword("password123")
			u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
			if err := users.Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			us := NewUserService(users, tokens, tx, verify, mail)
			if _, err := us.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err != nil {
				t.Fatal(err)
			}
			if action == "change" {
				if err := us.ChangePassword(ctx, u.ID, &ChangePasswordRequest{CurrentPassword: "password123", NewPassword: "updated-password"}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("reset"), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
				as := NewAuthService(users, tokens, verify, tx, newTestJWT(t), mail, nil)
				if err := as.ResetPassword(ctx, "reset", "updated-password"); err != nil {
					t.Fatal(err)
				}
			}
			if err := us.ConfirmEmailChange(ctx, mail.change); err == nil {
				t.Fatal("confirmation reauthorized using obsolete password")
			}
			got, _ := users.GetByID(ctx, u.ID)
			if got.Email != "old@example.com" || got.PendingEmail != "" {
				t.Fatal("password change retained pending takeover")
			}
		})
	}
}

type simultaneousVerificationReads struct {
	repository.VerificationRepository
	readers *sync.WaitGroup
}

func (r simultaneousVerificationReads) GetByHash(ctx context.Context, hash, kind string) (*repository.VerificationToken, error) {
	token, err := r.VerificationRepository.GetByHash(ctx, hash, kind)
	r.readers.Done()
	r.readers.Wait()
	return token, err
}

type simultaneousRegistrationReads struct {
	repository.UserRepository
	readers *sync.WaitGroup
}

func (r simultaneousRegistrationReads) GetDeletedByEmail(ctx context.Context, email string) (*model.User, error) {
	user, err := r.UserRepository.GetDeletedByEmail(ctx, email)
	r.readers.Done()
	r.readers.Wait()
	return user, err
}
func TestLifecycleConcurrentRegistrationRemainsOpaque(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	var readers sync.WaitGroup
	readers.Add(2)
	svc := NewAuthService(simultaneousRegistrationReads{users, &readers}, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), nil, nil, nil)
	results := make(chan *RegistrationResponse, 2)
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := svc.Register(ctx, &RegisterRequest{Email: "race@example.com", Password: "password123"})
			results <- res
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var previous *RegistrationResponse
	for res := range results {
		if res == nil || previous != nil && *res != *previous {
			t.Fatal("registration race exposed account existence")
		}
		previous = res
	}
	var count int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("created %d duplicate accounts", count)
	}
}
