package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"github.com/stripe/stripe-go/v81"
	stripesub "github.com/stripe/stripe-go/v81/subscription"

	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/config"
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

var pool *pgxpool.Pool

func main() {
	root := &cobra.Command{
		Use:   "shellvault-cli",
		Short: "ShellVault Server Admin CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip DB connection for help commands
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			p, err := pgxpool.New(context.Background(), cfg.Database.URL)
			if err != nil {
				return fmt.Errorf("database: %w", err)
			}
			pool = p
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if pool != nil {
				pool.Close()
			}
		},
	}

	root.AddCommand(userCmd())
	root.AddCommand(billingCmd())
	root.AddCommand(backupCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ============================================================
// USER COMMANDS
// ============================================================

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "User management",
	}

	cmd.AddCommand(userListCmd())
	cmd.AddCommand(userInfoCmd())
	cmd.AddCommand(userDeleteCmd())
	cmd.AddCommand(userDeactivateCmd())
	cmd.AddCommand(userActivateCmd())
	cmd.AddCommand(userLogoutCmd())
	cmd.AddCommand(userDevicesCmd())
	cmd.AddCommand(userDeleteDeviceCmd())
	cmd.AddCommand(userAuditCmd())
	cmd.AddCommand(userResetVaultCmd())

	return cmd
}

func userListCmd() *cobra.Command {
	var showDeleted bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			query := `SELECT id, email, verified, created_at, deleted_at FROM users`
			if !showDeleted {
				query += ` WHERE deleted_at IS NULL`
			}
			query += ` ORDER BY created_at DESC`

			rows, err := pool.Query(ctx, query)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Printf("%-36s  %-30s  %-8s  %-20s  %s\n",
				"ID", "EMAIL", "VERIFIED", "CREATED", "STATUS")
			fmt.Println(strings.Repeat("─", 120))

			count := 0
			for rows.Next() {
				var id uuid.UUID
				var email string
				var verified bool
				var createdAt time.Time
				var deletedAt *time.Time

				if err := rows.Scan(&id, &email, &verified, &createdAt, &deletedAt); err != nil {
					return fmt.Errorf("scan: %w", err)
				}

				status := "active"
				if deletedAt != nil {
					status = "deleted"
				}

				verifiedStr := "no"
				if verified {
					verifiedStr = "yes"
				}

				fmt.Printf("%-36s  %-30s  %-8s  %-20s  %s\n",
					id, truncate(email, 30), verifiedStr,
					createdAt.Format("2006-01-02 15:04"), status)
				count++
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}
			fmt.Printf("\nTotal: %d users\n", count)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showDeleted, "all", false, "Show deleted users too")
	return cmd
}

func userInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <email-or-id>",
		Short: "Show user details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			fmt.Printf("ID:         %s\n", user.id)
			fmt.Printf("Email:      %s\n", user.email)
			fmt.Printf("Verified:   %v\n", user.verified)
			fmt.Printf("Created:    %s\n", user.createdAt.Format(time.RFC3339))
			fmt.Printf("Updated:    %s\n", user.updatedAt.Format(time.RFC3339))
			if user.deletedAt != nil {
				fmt.Printf("Deleted:    %s\n", user.deletedAt.Format(time.RFC3339))
			}

			// Subscription
			var subProvider, subProviderSubID, subStatus string
			var periodStart, periodEnd *time.Time
			var subCreatedAt time.Time
			err = pool.QueryRow(ctx,
				`SELECT provider, provider_sub_id, status, current_period_start, current_period_end, created_at
				 FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, user.id).
				Scan(&subProvider, &subProviderSubID, &subStatus, &periodStart, &periodEnd, &subCreatedAt)
			fmt.Println("\nSubscription:")
			if err != nil {
				fmt.Println("  (none)")
			} else {
				fmt.Printf("  Provider:     %s\n", subProvider)
				fmt.Printf("  Provider ID:  %s\n", subProviderSubID)
				fmt.Printf("  Status:       %s\n", subStatus)
				if periodStart != nil {
					fmt.Printf("  Period Start: %s\n", periodStart.Format(time.RFC3339))
				}
				if periodEnd != nil {
					fmt.Printf("  Period End:   %s\n", periodEnd.Format(time.RFC3339))
					if time.Now().After(*periodEnd) {
						fmt.Printf("  !! EXPIRED\n")
					}
				}
				fmt.Printf("  Created:      %s\n", subCreatedAt.Format(time.RFC3339))
			}

			// Vault
			var vaultVersion int
			var vaultUpdated time.Time
			var blobLen *int
			err = pool.QueryRow(ctx,
				`SELECT version, octet_length(blob), updated_at FROM vaults WHERE user_id = $1`,
				user.id).Scan(&vaultVersion, &blobLen, &vaultUpdated)
			fmt.Println("\nVault:")
			if err != nil {
				fmt.Println("  (no vault)")
			} else {
				size := 0
				if blobLen != nil {
					size = *blobLen
				}
				fmt.Printf("  Version:  %d\n", vaultVersion)
				fmt.Printf("  Size:     %s\n", formatBytes(size))
				fmt.Printf("  Updated:  %s\n", vaultUpdated.Format(time.RFC3339))
			}

			// Devices
			deviceRows, err := pool.Query(ctx,
				`SELECT name, platform, last_sync FROM devices WHERE user_id = $1`, user.id)
			if err == nil {
				defer deviceRows.Close()
				fmt.Println("\nDevices:")
				hasDevices := false
				for deviceRows.Next() {
					var name, platform string
					var lastSync *time.Time
					if err := deviceRows.Scan(&name, &platform, &lastSync); err != nil {
						continue
					}
					syncStr := "never"
					if lastSync != nil {
						syncStr = lastSync.Format("2006-01-02 15:04")
					}
					fmt.Printf("  - %s (%s) — last sync: %s\n", name, platform, syncStr)
					hasDevices = true
				}
				if err := deviceRows.Err(); err != nil {
					return fmt.Errorf("iterating device rows: %w", err)
				}
				if !hasDevices {
					fmt.Println("  (none)")
				}
			}

			return nil
		},
	}
}

func userDeleteCmd() *cobra.Command {
	var hard bool
	cmd := &cobra.Command{
		Use:   "delete <email-or-id>",
		Short: "Delete a user (soft delete by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			if hard {
				fmt.Printf("HARD DELETE user %s (%s)? This is IRREVERSIBLE!\n", user.email, user.id)
				if !confirm() {
					fmt.Println("Aborted.")
					return nil
				}
				// Hard delete cascades via foreign keys
				_, err = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.id)
				if err != nil {
					return fmt.Errorf("hard delete: %w", err)
				}
				fmt.Printf("User %s permanently deleted.\n", user.email)
			} else {
				_, err = pool.Exec(ctx,
					`UPDATE users SET deleted_at = now() WHERE id = $1`, user.id)
				if err != nil {
					return fmt.Errorf("soft delete: %w", err)
				}
				// Revoke all tokens
				if _, err := pool.Exec(ctx,
					`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1`, user.id); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to revoke tokens for %s: %v\n", user.email, err)
				}
				fmt.Printf("User %s soft-deleted. Data will be purged after 30 days.\n", user.email)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&hard, "hard", false, "Permanently delete user and all data (CASCADE)")
	return cmd
}

func userDeactivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deactivate <email-or-id>",
		Short: "Deactivate a user (soft delete + revoke tokens)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			if user.deletedAt != nil {
				fmt.Printf("User %s is already deactivated.\n", user.email)
				return nil
			}

			_, err = pool.Exec(ctx,
				`UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1`, user.id)
			if err != nil {
				return fmt.Errorf("deactivate: %w", err)
			}
			if _, err := pool.Exec(ctx,
				`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1`, user.id); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to revoke tokens for %s: %v\n", user.email, err)
			}

			fmt.Printf("User %s deactivated. All sessions revoked.\n", user.email)
			return nil
		},
	}
}

func userActivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate <email-or-id>",
		Short: "Reactivate a deactivated user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Find user even if deleted
			var id uuid.UUID
			var email string
			var deletedAt *time.Time
			query := `SELECT id, email, deleted_at FROM users WHERE `
			arg := args[0]
			if isUUID(arg) {
				query += `id = $1`
			} else {
				query += `email = $1`
			}
			err := pool.QueryRow(ctx, query, arg).Scan(&id, &email, &deletedAt)
			if err != nil {
				return fmt.Errorf("user not found: %s", arg)
			}

			if deletedAt == nil {
				fmt.Printf("User %s is already active.\n", email)
				return nil
			}

			_, err = pool.Exec(ctx,
				`UPDATE users SET deleted_at = NULL, updated_at = now() WHERE id = $1`, id)
			if err != nil {
				return fmt.Errorf("activate: %w", err)
			}

			fmt.Printf("User %s reactivated.\n", email)
			return nil
		},
	}
}

func userLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout <email-or-id>",
		Short: "Revoke all sessions for a user (without deactivating)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			result, err := pool.Exec(ctx,
				`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, user.id)
			if err != nil {
				return fmt.Errorf("revoking tokens: %w", err)
			}

			fmt.Printf("Revoked %d session(s) for %s. User remains active.\n",
				result.RowsAffected(), user.email)
			return nil
		},
	}
}

func userDevicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "devices <email-or-id>",
		Short: "List devices for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			rows, err := pool.Query(ctx,
				`SELECT id, name, platform, last_sync, created_at FROM devices WHERE user_id = $1 ORDER BY created_at DESC`,
				user.id)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Printf("Devices for: %s (%s)\n\n", user.email, user.id)
			fmt.Printf("%-36s  %-20s  %-10s  %-20s  %s\n",
				"ID", "NAME", "PLATFORM", "LAST SYNC", "REGISTERED")
			fmt.Println(strings.Repeat("─", 120))

			count := 0
			for rows.Next() {
				var id uuid.UUID
				var name, platform string
				var lastSync *time.Time
				var createdAt time.Time
				if err := rows.Scan(&id, &name, &platform, &lastSync, &createdAt); err != nil {
					continue
				}
				syncStr := "never"
				if lastSync != nil {
					syncStr = lastSync.Format("2006-01-02 15:04")
				}
				fmt.Printf("%-36s  %-20s  %-10s  %-20s  %s\n",
					id, truncate(name, 20), platform, syncStr,
					createdAt.Format("2006-01-02 15:04"))
				count++
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}
			if count == 0 {
				fmt.Println("  No devices registered.")
			} else {
				fmt.Printf("\nTotal: %d device(s)\n", count)
			}
			return nil
		},
	}
}

func userDeleteDeviceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete-device <email-or-id> <device-id>",
		Short: "Remove a device from a user",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			deviceID := args[1]
			result, err := pool.Exec(ctx,
				`DELETE FROM devices WHERE id = $1 AND user_id = $2`, deviceID, user.id)
			if err != nil {
				return fmt.Errorf("deleting device: %w", err)
			}
			if result.RowsAffected() == 0 {
				return fmt.Errorf("device %s not found for user %s", deviceID, user.email)
			}

			fmt.Printf("Device %s removed from user %s.\n", deviceID, user.email)
			return nil
		},
	}
}

func userAuditCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "audit <email-or-id>",
		Short: "Show audit log for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			rows, err := pool.Query(ctx,
				`SELECT timestamp, level, category, action, actor_email, ip_address, details
				 FROM audit_logs WHERE actor_id = $1
				 ORDER BY timestamp DESC LIMIT $2`,
				user.id, limit)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Printf("Audit log for: %s (%s)\n\n", user.email, user.id)
			fmt.Printf("%-20s  %-6s  %-15s  %-20s  %-15s  %s\n",
				"TIMESTAMP", "LEVEL", "CATEGORY", "ACTION", "IP", "DETAILS")
			fmt.Println(strings.Repeat("─", 120))

			count := 0
			for rows.Next() {
				var ts time.Time
				var level, category, action, actorEmail, ip string
				var details []byte
				if err := rows.Scan(&ts, &level, &category, &action, &actorEmail, &ip, &details); err != nil {
					continue
				}
				detailStr := ""
				if len(details) > 2 { // skip empty "{}"
					detailStr = truncate(string(details), 30)
				}
				fmt.Printf("%-20s  %-6s  %-15s  %-20s  %-15s  %s\n",
					ts.Format("2006-01-02 15:04:05"),
					level, category, action,
					truncate(ip, 15), detailStr)
				count++
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}
			if count == 0 {
				fmt.Println("  No audit entries found.")
			} else {
				fmt.Printf("\nShowing %d of last %d entries.\n", count, limit)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "Number of entries to show")
	return cmd
}

func userResetVaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-vault <email-or-id>",
		Short: "Delete a user's encrypted vault (irreversible)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			fmt.Printf("DELETE vault for %s? This removes all encrypted data and history!\n", user.email)
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			_, _ = pool.Exec(ctx, `DELETE FROM vault_history WHERE user_id = $1`, user.id)
			result, err := pool.Exec(ctx, `DELETE FROM vaults WHERE user_id = $1`, user.id)
			if err != nil {
				return fmt.Errorf("deleting vault: %w", err)
			}

			if result.RowsAffected() == 0 {
				fmt.Printf("No vault found for %s.\n", user.email)
			} else {
				fmt.Printf("Vault deleted for %s (including history).\n", user.email)
			}
			return nil
		},
	}
}

// ============================================================
// BILLING COMMANDS
// ============================================================

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

			// Apple/Google: warn
			var appleCount, googleCount int
			_ = pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM subscriptions WHERE provider = 'apple' AND status = 'active'`).Scan(&appleCount)
			_ = pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM subscriptions WHERE provider = 'google' AND status = 'active'`).Scan(&googleCount)

			if appleCount > 0 {
				fmt.Printf("Apple: %d active subscription(s) — verification not yet implemented\n", appleCount)
			}
			if googleCount > 0 {
				fmt.Printf("Google: %d active subscription(s) — verification not yet implemented\n", googleCount)
			}

			fmt.Println("\nSync complete.")
			return nil
		},
	}
}

// ============================================================
// BACKUP COMMANDS
// ============================================================

func backupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Database backup & restore",
	}
	cmd.AddCommand(backupCreateCmd())
	cmd.AddCommand(backupRestoreCmd())
	cmd.AddCommand(backupListCmd())
	cmd.AddCommand(backupAutoCmd())
	return cmd
}

func backupCreateCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a database backup (pg_dump + manifest)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			dir := cfg.Backup.Dir
			if output != "" {
				dir = output
			}

			path, err := createBackup(cfg.Database.URL, dir)
			if err != nil {
				return err
			}
			fmt.Printf("Backup created: %s\n", path)

			// Create manifest alongside the SQL dump
			ctx := context.Background()
			manifest, err := captureManifest(ctx, pool)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: manifest creation failed: %v\n", err)
				return nil
			}
			manifestPath := strings.TrimSuffix(path, ".sql.gz") + ".manifest.json"
			if err := writeManifestFile(manifest, manifestPath); err != nil {
				fmt.Fprintf(os.Stderr, "warning: manifest write failed: %v\n", err)
				return nil
			}
			fmt.Printf("Manifest created: %s (%d deleted users, %d canceled subs, %d revoked tokens)\n",
				manifestPath, len(manifest.DeletedUsers), len(manifest.CanceledSubs), manifest.RevokedTokenCount)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output directory (default from BACKUP_DIR)")
	return cmd
}

func backupRestoreCmd() *cobra.Command {
	var skipReconcile bool
	cmd := &cobra.Command{
		Use:   "restore <file>",
		Short: "Restore database from a backup file (with reconciliation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			file := args[0]

			fmt.Printf("RESTORE database from %s?\n", file)
			fmt.Println("WARNING: This will overwrite the current database!")
			fmt.Println("Deleted accounts and canceled subscriptions will be preserved.")
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			ctx := context.Background()

			// Step 1: Pre-restore snapshot
			fmt.Println("\n[1/5] Capturing pre-restore manifest...")
			preManifest, err := captureManifest(ctx, pool)
			if err != nil {
				return fmt.Errorf("pre-restore manifest: %w", err)
			}
			fmt.Printf("  Captured: %d deleted users, %d canceled subs, %d revoked tokens\n",
				len(preManifest.DeletedUsers), len(preManifest.CanceledSubs), preManifest.RevokedTokenCount)

			// Step 2: Restore SQL dump
			fmt.Println("\n[2/5] Restoring database...")
			if err := restoreBackup(cfg.Database.URL, file); err != nil {
				return err
			}
			fmt.Println("  Database restored.")

			if skipReconcile {
				fmt.Println("\nReconciliation skipped (--no-reconcile).")
				return nil
			}

			// Reconnect pool after restore
			pool.Close()
			pool, err = pgxpool.New(ctx, cfg.Database.URL)
			if err != nil {
				return fmt.Errorf("reconnecting after restore: %w", err)
			}

			// Step 3: Load backup manifest (if exists alongside the backup file)
			fmt.Println("\n[3/5] Loading backup manifest...")
			var backupManifest *restoreManifest
			manifestPath := strings.TrimSuffix(file, ".sql.gz") + ".manifest.json"
			if bm, err := loadManifestFile(manifestPath); err == nil {
				backupManifest = bm
				fmt.Printf("  Loaded: %d deleted users, %d canceled subs\n",
					len(bm.DeletedUsers), len(bm.CanceledSubs))
			} else {
				fmt.Println("  No backup manifest found, using pre-restore snapshot only.")
			}

			// Step 4: Merge and apply
			fmt.Println("\n[4/5] Applying reconciliation...")
			merged := preManifest
			if backupManifest != nil {
				merged = mergeManifests(preManifest, backupManifest)
			}
			deletedUsers, canceledSubs, revokedTokens := applyManifest(ctx, pool, merged)
			fmt.Printf("  Re-deleted %d user(s), re-canceled %d subscription(s), re-revoked %d token(s)\n",
				deletedUsers, canceledSubs, revokedTokens)

			// Step 5: Stripe reconciliation (if configured)
			fmt.Println("\n[5/5] Stripe reconciliation...")
			if cfg.Billing.StripeSecretKey != "" {
				checked, corrected, err := reconcileStripe(ctx, pool, cfg.Billing.StripeSecretKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  warning: Stripe reconciliation error: %v\n", err)
				} else {
					fmt.Printf("  Checked %d Stripe subscription(s), corrected %d\n", checked, corrected)
				}
			} else {
				fmt.Println("  Skipped (STRIPE_SECRET_KEY not set)")
			}

			fmt.Println("\nRestore complete with reconciliation.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&skipReconcile, "no-reconcile", false, "Skip post-restore reconciliation")
	return cmd
}

func backupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available backups",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			entries, err := os.ReadDir(cfg.Backup.Dir)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Println("No backups found. Backup directory does not exist.")
					return nil
				}
				return fmt.Errorf("reading backup dir: %w", err)
			}

			fmt.Printf("%-45s  %-12s  %s\n", "FILE", "SIZE", "CREATED")
			fmt.Println(strings.Repeat("─", 80))

			count := 0
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql.gz") {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				fmt.Printf("%-45s  %-12s  %s\n",
					e.Name(),
					formatBytes(int(info.Size())),
					info.ModTime().Format("2006-01-02 15:04:05"))
				count++
			}

			if count == 0 {
				fmt.Println("No backups found.")
			} else {
				fmt.Printf("\nTotal: %d backup(s)\n", count)
			}
			return nil
		},
	}
}

func backupAutoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auto",
		Short: "Start automatic backup daemon (reads BACKUP_INTERVAL from ENV)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			fmt.Printf("Auto-backup started\n")
			fmt.Printf("  Directory: %s\n", cfg.Backup.Dir)
			fmt.Printf("  Interval:  %s\n", cfg.Backup.Interval)
			fmt.Printf("  Retention: %d backups\n", cfg.Backup.Retention)
			fmt.Println()

			// First backup immediately
			path, err := createBackup(cfg.Database.URL, cfg.Backup.Dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "initial backup failed: %v\n", err)
			} else {
				fmt.Printf("[%s] Backup created: %s\n", time.Now().Format(time.RFC3339), path)
				createBackupManifest(path)
			}
			pruneBackups(cfg.Backup.Dir, cfg.Backup.Retention)

			ticker := time.NewTicker(cfg.Backup.Interval)
			defer ticker.Stop()

			for t := range ticker.C {
				path, err := createBackup(cfg.Database.URL, cfg.Backup.Dir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] backup failed: %v\n", t.Format(time.RFC3339), err)
					continue
				}
				fmt.Printf("[%s] Backup created: %s\n", t.Format(time.RFC3339), path)
				createBackupManifest(path)
				pruneBackups(cfg.Backup.Dir, cfg.Backup.Retention)
			}
			return nil
		},
	}
}

// ============================================================
// BACKUP HELPERS
// ============================================================

func createBackup(databaseURL, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating backup dir: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("shellvault_%s.sql.gz", timestamp)
	path := filepath.Join(dir, filename)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Safe exec: no shell interpolation
	dump := exec.CommandContext(ctx, "pg_dump", "--no-owner", "--no-acl", databaseURL)
	gzipCmd := exec.CommandContext(ctx, "gzip")

	// Pipe pg_dump stdout into gzip stdin
	pipe, err := dump.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("creating pipe: %w", err)
	}
	gzipCmd.Stdin = pipe

	outFile, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	gzipCmd.Stdout = outFile

	var dumpStderr, gzipStderr strings.Builder
	dump.Stderr = &dumpStderr
	gzipCmd.Stderr = &gzipStderr

	if err := gzipCmd.Start(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("starting gzip: %w", err)
	}
	if err := dump.Run(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("pg_dump failed: %w\n%s", err, dumpStderr.String())
	}
	if err := gzipCmd.Wait(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("gzip failed: %w\n%s", err, gzipStderr.String())
	}

	// Verify file was created and has content
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		_ = os.Remove(path)
		return "", fmt.Errorf("backup file is empty or missing")
	}

	return path, nil
}

func createBackupManifest(backupPath string) {
	ctx := context.Background()
	manifest, err := captureManifest(ctx, pool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: manifest creation failed: %v\n", err)
		return
	}
	manifestPath := strings.TrimSuffix(backupPath, ".sql.gz") + ".manifest.json"
	if err := writeManifestFile(manifest, manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: manifest write failed: %v\n", err)
		return
	}
	fmt.Printf("  Manifest: %d deleted users, %d canceled subs\n",
		len(manifest.DeletedUsers), len(manifest.CanceledSubs))
}

func restoreBackup(databaseURL, file string) error {
	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("backup file not found: %s", file)
	}
	if info.Size() == 0 {
		return fmt.Errorf("backup file is empty: %s", file)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Safe exec: no shell interpolation
	gunzip := exec.CommandContext(ctx, "gunzip", "-c", file)
	psql := exec.CommandContext(ctx, "psql", databaseURL)

	// Pipe gunzip stdout into psql stdin
	pipe, err := gunzip.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}
	psql.Stdin = pipe

	var gunzipStderr, psqlStderr strings.Builder
	gunzip.Stderr = &gunzipStderr
	psql.Stderr = &psqlStderr

	if err := psql.Start(); err != nil {
		return fmt.Errorf("starting psql: %w", err)
	}
	if err := gunzip.Run(); err != nil {
		return fmt.Errorf("gunzip failed: %w\n%s", err, gunzipStderr.String())
	}
	if err := psql.Wait(); err != nil {
		return fmt.Errorf("psql failed: %w\n%s", err, psqlStderr.String())
	}
	return nil
}

func pruneBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql.gz") {
			backups = append(backups, e)
		}
	}

	if len(backups) <= keep {
		return
	}

	// Entries are sorted alphabetically (= chronologically due to timestamp format)
	toDelete := backups[:len(backups)-keep]
	for _, e := range toDelete {
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err == nil {
			fmt.Printf("  Pruned old backup: %s\n", e.Name())
		}
	}
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

// ============================================================
// HELPERS
// ============================================================

type userRow struct {
	id        uuid.UUID
	email     string
	verified  bool
	createdAt time.Time
	updatedAt time.Time
	deletedAt *time.Time
}

func findUser(ctx context.Context, search string) (*userRow, error) {
	query := `SELECT id, email, verified, created_at, updated_at, deleted_at FROM users WHERE `
	if isUUID(search) {
		query += `id = $1`
	} else {
		query += `email = $1`
	}

	var u userRow
	err := pool.QueryRow(ctx, query, search).Scan(
		&u.id, &u.email, &u.verified, &u.createdAt, &u.updatedAt, &u.deletedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %s", search)
	}
	return &u, nil
}

func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) > max {
		return string(runes[:max-3]) + "..."
	}
	return s
}

func formatBytes(b int) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func confirm() bool {
	fmt.Print("Type 'yes' to confirm: ")
	var input string
	_, _ = fmt.Scanln(&input)
	return strings.TrimSpace(strings.ToLower(input)) == "yes"
}
