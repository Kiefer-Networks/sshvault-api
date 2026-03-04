package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stripe/stripe-go/v81"
	stripesub "github.com/stripe/stripe-go/v81/subscription"
)

// ============================================================
// MANIFEST TYPES
// ============================================================

type restoreManifest struct {
	CreatedAt         time.Time      `json:"created_at"`
	DeletedUsers      []manifestUser `json:"deleted_users"`
	CanceledSubs      []manifestSub  `json:"canceled_subscriptions"`
	RevokedTokenCount int            `json:"revoked_token_count"`
}

type manifestUser struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	DeletedAt time.Time `json:"deleted_at"`
}

type manifestSub struct {
	ID            uuid.UUID `json:"id"`
	UserID        uuid.UUID `json:"user_id"`
	Provider      string    `json:"provider"`
	ProviderSubID string    `json:"provider_sub_id"`
	Status        string    `json:"status"`
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

	// Canceled/expired subscriptions
	subRows, err := p.Query(ctx,
		`SELECT id, user_id, provider, provider_sub_id, status
		 FROM subscriptions WHERE status IN ('canceled', 'expired')`)
	if err != nil {
		return nil, fmt.Errorf("querying canceled subs: %w", err)
	}
	defer subRows.Close()
	for subRows.Next() {
		var s manifestSub
		if err := subRows.Scan(&s.ID, &s.UserID, &s.Provider, &s.ProviderSubID, &s.Status); err != nil {
			return nil, fmt.Errorf("scanning canceled sub: %w", err)
		}
		m.CanceledSubs = append(m.CanceledSubs, s)
	}
	if err := subRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating canceled subs: %w", err)
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

	// Union of canceled subs (deduplicate by ID)
	subSeen := make(map[uuid.UUID]bool)
	for _, s := range a.CanceledSubs {
		merged.CanceledSubs = append(merged.CanceledSubs, s)
		subSeen[s.ID] = true
	}
	for _, s := range b.CanceledSubs {
		if !subSeen[s.ID] {
			merged.CanceledSubs = append(merged.CanceledSubs, s)
		}
	}

	// Take the higher revoked token count
	merged.RevokedTokenCount = a.RevokedTokenCount
	if b.RevokedTokenCount > merged.RevokedTokenCount {
		merged.RevokedTokenCount = b.RevokedTokenCount
	}

	return merged
}

func applyManifest(ctx context.Context, p *pgxpool.Pool, m *restoreManifest) (deletedUsers, canceledSubs, revokedTokens int) {
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

	// Re-cancel subscriptions
	for _, s := range m.CanceledSubs {
		result, err := p.Exec(ctx,
			`UPDATE subscriptions SET status = $1, updated_at = now()
			 WHERE id = $2 AND status NOT IN ('canceled', 'expired')`, s.Status, s.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to re-cancel sub %s: %v\n", s.ID, err)
			continue
		}
		if result.RowsAffected() > 0 {
			canceledSubs++
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

func reconcileStripe(ctx context.Context, p *pgxpool.Pool, stripeKey string) (checked, corrected int, err error) {
	stripe.Key = stripeKey

	rows, err := p.Query(ctx,
		`SELECT id, provider_sub_id FROM subscriptions
		 WHERE provider = 'stripe' AND status = 'active' AND provider_sub_id != ''`)
	if err != nil {
		return 0, 0, fmt.Errorf("querying active stripe subs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var subID uuid.UUID
		var providerSubID string
		if err := rows.Scan(&subID, &providerSubID); err != nil {
			continue
		}
		checked++

		stripeSub, err := stripesub.Get(providerSubID, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: Stripe API error for %s: %v\n", providerSubID, err)
			continue
		}

		var newStatus string
		switch stripeSub.Status {
		case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusTrialing:
			continue // matches
		case stripe.SubscriptionStatusCanceled:
			newStatus = "canceled"
		case stripe.SubscriptionStatusPastDue:
			newStatus = "past_due"
		case stripe.SubscriptionStatusUnpaid, stripe.SubscriptionStatusIncompleteExpired:
			newStatus = "expired"
		default:
			newStatus = "canceled"
		}

		if _, err := p.Exec(ctx,
			`UPDATE subscriptions SET status = $1, updated_at = now() WHERE id = $2`,
			newStatus, subID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to update sub %s: %v\n", subID, err)
		} else {
			fmt.Printf("  Corrected: %s → %s (Stripe: %s)\n", providerSubID, newStatus, stripeSub.Status)
			corrected++
		}
	}
	if err := rows.Err(); err != nil {
		return checked, corrected, fmt.Errorf("iterating rows: %w", err)
	}

	return checked, corrected, nil
}
