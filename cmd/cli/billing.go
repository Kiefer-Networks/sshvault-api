package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

func billingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "billing",
		Short: "Subscription & billing management",
	}
	cmd.AddCommand(billingInfoCmd())
	cmd.AddCommand(billingSetCmd())
	cmd.AddCommand(billingRevokeCmd())
	cmd.AddCommand(billingSyncCmd())
	return cmd
}

func billingInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <email-or-id>",
		Short: "Show billing status for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			rows, err := pool.Query(ctx,
				`SELECT id, provider, provider_sub_id, status, current_period_start, current_period_end, created_at
				 FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC`, user.id)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Printf("Billing for: %s (%s)\n\n", user.email, user.id)

			hasSubs := false
			for rows.Next() {
				var subID uuid.UUID
				var provider, providerSubID, status string
				var periodStart, periodEnd *time.Time
				var createdAt time.Time
				if err := rows.Scan(&subID, &provider, &providerSubID, &status, &periodStart, &periodEnd, &createdAt); err != nil {
					continue
				}

				fmt.Printf("  Subscription: %s\n", subID)
				fmt.Printf("  Provider:     %s\n", provider)
				fmt.Printf("  Provider ID:  %s\n", providerSubID)
				fmt.Printf("  Status:       %s\n", status)
				if periodStart != nil {
					fmt.Printf("  Period Start: %s\n", periodStart.Format(time.RFC3339))
				}
				if periodEnd != nil {
					fmt.Printf("  Period End:   %s\n", periodEnd.Format(time.RFC3339))
					if time.Now().After(*periodEnd) {
						fmt.Printf("  ⚠  EXPIRED\n")
					}
				}
				fmt.Printf("  Created:      %s\n", createdAt.Format(time.RFC3339))
				fmt.Println()
				hasSubs = true
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}

			if !hasSubs {
				fmt.Println("  No subscriptions found.")
			}
			return nil
		},
	}
}

func billingSetCmd() *cobra.Command {
	var (
		provider string
		status   string
		days     int
	)

	cmd := &cobra.Command{
		Use:   "set <email-or-id>",
		Short: "Create or update a subscription for a user",
		Long: `Sets a subscription for a user. Use --provider=manual for admin-granted subs.

Examples:
  shellvault-cli billing set user@example.com --days 365
  shellvault-cli billing set user@example.com --provider stripe --status active --days 30`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			now := time.Now()
			periodStart := now
			periodEnd := now.Add(time.Duration(days) * 24 * time.Hour)
			providerSubID := fmt.Sprintf("manual_%s_%d", user.id, now.Unix())

			// Check if subscription already exists
			var existingID uuid.UUID
			err = pool.QueryRow(ctx,
				`SELECT id FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
				user.id).Scan(&existingID)

			if err == nil {
				// Update existing
				_, err = pool.Exec(ctx,
					`UPDATE subscriptions SET status = $1, provider = $2,
					 current_period_start = $3, current_period_end = $4, updated_at = now()
					 WHERE id = $5`,
					status, provider, periodStart, periodEnd, existingID)
				if err != nil {
					return fmt.Errorf("update: %w", err)
				}
				fmt.Printf("Updated subscription for %s\n", user.email)
			} else {
				// Create new
				_, err = pool.Exec(ctx,
					`INSERT INTO subscriptions (id, user_id, provider, provider_sub_id, status,
					 current_period_start, current_period_end, created_at, updated_at)
					 VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())`,
					uuid.New(), user.id, provider, providerSubID, status,
					periodStart, periodEnd)
				if err != nil {
					return fmt.Errorf("create: %w", err)
				}
				fmt.Printf("Created subscription for %s\n", user.email)
			}

			fmt.Printf("  Provider: %s\n", provider)
			fmt.Printf("  Status:   %s\n", status)
			fmt.Printf("  Period:   %s → %s (%d days)\n",
				periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"), days)
			return nil
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "manual", "Subscription provider (manual, stripe, apple, google)")
	cmd.Flags().StringVar(&status, "status", "active", "Subscription status (active, canceled, expired, past_due)")
	cmd.Flags().IntVar(&days, "days", 365, "Subscription duration in days from now")
	return cmd
}

func billingRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <email-or-id>",
		Short: "Revoke all subscriptions for a user (cancels at Stripe with prorated refund)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			// Find active subscriptions with their provider details
			rows, err := pool.Query(ctx,
				`SELECT id, provider, provider_sub_id, status FROM subscriptions
				 WHERE user_id = $1 AND status IN ('active', 'past_due')`,
				user.id)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			cfg, cfgErr := config.Load()

			count := 0
			for rows.Next() {
				var subID uuid.UUID
				var provider, providerSubID, status string
				if err := rows.Scan(&subID, &provider, &providerSubID, &status); err != nil {
					continue
				}

				// Cancel at Stripe API (includes prorated refund)
				if provider == "stripe" && providerSubID != "" && cfgErr == nil && cfg.Billing.StripeSecretKey != "" {
					sp := billing.NewStripeProvider(cfg.Billing.StripeSecretKey, "", "", "", nil, nil)
					if err := sp.CancelSubscription(ctx, providerSubID); err != nil {
						fmt.Fprintf(os.Stderr, "  warning: Stripe cancellation failed for %s: %v\n", providerSubID, err)
					} else {
						fmt.Printf("  Stripe subscription %s canceled (prorated refund issued)\n", providerSubID)
					}
				}

				// Update local DB status
				if _, err := pool.Exec(ctx,
					`UPDATE subscriptions SET status = 'canceled', updated_at = now() WHERE id = $1`,
					subID); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: failed to update DB for %s: %v\n", subID, err)
				}
				count++
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}

			if count == 0 {
				fmt.Printf("No active subscriptions found for %s.\n", user.email)
			} else {
				fmt.Printf("Revoked %d subscription(s) for %s.\n", count, user.email)
			}
			return nil
		},
	}
}

func billingSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Reconcile all active subscriptions against provider APIs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ctx := context.Background()

			// Count active subscriptions by provider
			rows, err := pool.Query(ctx,
				`SELECT provider, COUNT(*) FROM subscriptions WHERE status = 'active' GROUP BY provider`)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Println("Active subscriptions by provider:")
			for rows.Next() {
				var provider string
				var count int
				if err := rows.Scan(&provider, &count); err != nil {
					continue
				}
				fmt.Printf("  %s: %d\n", provider, count)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}
			fmt.Println()

			// Stripe sync
			if cfg.Billing.StripeSecretKey != "" {
				fmt.Println("Syncing Stripe subscriptions...")
				checked, corrected, err := reconcileStripe(ctx, pool, cfg.Billing.StripeSecretKey)
				if err != nil {
					return fmt.Errorf("stripe sync: %w", err)
				}
				fmt.Printf("  Checked: %d, Corrected: %d\n\n", checked, corrected)
			} else {
				fmt.Println("Stripe: skipped (STRIPE_SECRET_KEY not set)")
			}

			// Google sync
			if cfg.Billing.GoogleServiceAcctPath != "" && cfg.Billing.GooglePackageName != "" {
				fmt.Println("Syncing Google Play subscriptions...")
				checked, corrected, syncErr := reconcileGoogle(ctx, cfg)
				if syncErr != nil {
					fmt.Fprintf(os.Stderr, "  Google sync error: %v\n", syncErr)
				} else {
					fmt.Printf("  Checked: %d, Corrected: %d\n\n", checked, corrected)
				}
			} else {
				var googleCount int
				_ = pool.QueryRow(ctx,
					`SELECT COUNT(*) FROM subscriptions WHERE provider = 'google' AND status = 'active'`).Scan(&googleCount)
				if googleCount > 0 {
					fmt.Printf("Google: %d active subscription(s) — GOOGLE_SERVICE_ACCOUNT_PATH / GOOGLE_PACKAGE_NAME not set\n", googleCount)
				}
			}

			// Apple sync
			if cfg.Billing.AppleKeyPath != "" && cfg.Billing.AppleKeyID != "" &&
				cfg.Billing.AppleIssuerID != "" && cfg.Billing.AppleBundleID != "" {
				fmt.Println("Syncing Apple subscriptions...")
				checked, corrected, syncErr := reconcileApple(ctx, cfg)
				if syncErr != nil {
					fmt.Fprintf(os.Stderr, "  Apple sync error: %v\n", syncErr)
				} else {
					fmt.Printf("  Checked: %d, Corrected: %d\n\n", checked, corrected)
				}
			} else {
				var appleCount int
				_ = pool.QueryRow(ctx,
					`SELECT COUNT(*) FROM subscriptions WHERE provider = 'apple' AND status = 'active'`).Scan(&appleCount)
				if appleCount > 0 {
					fmt.Printf("Apple: %d active subscription(s) — APPLE_KEY_PATH / APPLE_KEY_ID not set\n", appleCount)
				}
			}

			fmt.Println("\nSync complete.")
			return nil
		},
	}
}

// reconcileApple verifies all active Apple subscriptions against the
// App Store Server API and corrects stale statuses in the database.
func reconcileApple(ctx context.Context, cfg *config.Config) (checked, corrected int, err error) {
	subRepo := repository.NewSubscriptionRepository(pool)

	ap, err := billing.NewAppleProvider(
		cfg.Billing.AppleKeyPath,
		cfg.Billing.AppleKeyID,
		cfg.Billing.AppleIssuerID,
		cfg.Billing.AppleBundleID,
		cfg.Billing.AppleEnvironment,
		subRepo,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("init apple provider: %w", err)
	}

	rows, err := pool.Query(ctx,
		`SELECT id, provider_sub_id, status FROM subscriptions
		 WHERE provider = 'apple' AND status IN ('active', 'past_due')`)
	if err != nil {
		return 0, 0, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	type sub struct {
		id            uuid.UUID
		transactionID string
		status        string
	}
	var subs []sub
	for rows.Next() {
		var s sub
		if err := rows.Scan(&s.id, &s.transactionID, &s.status); err != nil {
			continue
		}
		subs = append(subs, s)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterating rows: %w", err)
	}

	for _, s := range subs {
		checked++
		info, err := ap.VerifyPurchase(ctx, s.transactionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to verify %s: %v\n", s.id, err)
			continue
		}

		newStatus := mapAppleStatusForSync(info.Status)
		if newStatus != s.status {
			if _, err := pool.Exec(ctx,
				`UPDATE subscriptions SET status = $1, updated_at = now() WHERE id = $2`,
				newStatus, s.id); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: failed to update %s: %v\n", s.id, err)
				continue
			}
			fmt.Printf("  corrected %s: %s → %s\n", s.id, s.status, newStatus)
			corrected++
		}
	}

	return checked, corrected, nil
}

func mapAppleStatusForSync(status int) string {
	switch status {
	case 1, 4: // Active, Grace Period
		return "active"
	case 2: // Expired
		return "expired"
	case 3: // Billing Retry
		return "past_due"
	case 5: // Revoked
		return "canceled"
	default:
		return "canceled"
	}
}

// reconcileGoogle verifies all active Google subscriptions against the
// Google Play Developer API and corrects stale statuses in the database.
func reconcileGoogle(ctx context.Context, cfg *config.Config) (checked, corrected int, err error) {
	subRepo := repository.NewSubscriptionRepository(pool)

	gp, err := billing.NewGoogleProvider(
		cfg.Billing.GoogleServiceAcctPath,
		cfg.Billing.GooglePackageName,
		subRepo,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("init google provider: %w", err)
	}

	rows, err := pool.Query(ctx,
		`SELECT id, provider_sub_id, status FROM subscriptions
		 WHERE provider = 'google' AND status IN ('active', 'past_due')`)
	if err != nil {
		return 0, 0, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	type sub struct {
		id            uuid.UUID
		purchaseToken string
		status        string
	}
	var subs []sub
	for rows.Next() {
		var s sub
		if err := rows.Scan(&s.id, &s.purchaseToken, &s.status); err != nil {
			continue
		}
		subs = append(subs, s)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterating rows: %w", err)
	}

	for _, s := range subs {
		checked++
		googleSub, err := gp.VerifyPurchase(ctx, s.purchaseToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to verify %s: %v\n", s.id, err)
			continue
		}

		// Map Google state to our status
		var newStatus string
		switch googleSub.SubscriptionState {
		case "SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD":
			newStatus = "active"
		case "SUBSCRIPTION_STATE_CANCELED", "SUBSCRIPTION_STATE_PAUSED":
			newStatus = "canceled"
		case "SUBSCRIPTION_STATE_ON_HOLD":
			newStatus = "past_due"
		case "SUBSCRIPTION_STATE_EXPIRED":
			newStatus = "expired"
		default:
			newStatus = "canceled"
		}

		if newStatus != s.status {
			if _, err := pool.Exec(ctx,
				`UPDATE subscriptions SET status = $1, updated_at = now() WHERE id = $2`,
				newStatus, s.id); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: failed to update %s: %v\n", s.id, err)
				continue
			}
			fmt.Printf("  corrected %s: %s → %s\n", s.id, s.status, newStatus)
			corrected++
		}
	}

	return checked, corrected, nil
}
