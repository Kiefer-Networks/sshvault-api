package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

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
	cmd.AddCommand(userTeleportCmd())

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

			// Teleport
			var teleportUnlocked bool
			err = pool.QueryRow(ctx,
				`SELECT teleport_unlocked FROM users WHERE id = $1`, user.id).
				Scan(&teleportUnlocked)
			fmt.Println("\nTeleport:")
			if err != nil {
				fmt.Println("  (unknown)")
			} else {
				fmt.Printf("  Unlocked: %v\n", teleportUnlocked)
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

func userTeleportCmd() *cobra.Command {
	var unlock, lock bool
	cmd := &cobra.Command{
		Use:   "teleport <email-or-id>",
		Short: "Manage Teleport addon access for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !unlock && !lock {
				return fmt.Errorf("specify --unlock or --lock")
			}
			if unlock && lock {
				return fmt.Errorf("--unlock and --lock are mutually exclusive")
			}

			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			value := unlock
			_, err = pool.Exec(ctx,
				`UPDATE users SET teleport_unlocked = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL`,
				value, user.id)
			if err != nil {
				return fmt.Errorf("updating teleport status: %w", err)
			}

			status := "locked"
			if value {
				status = "unlocked"
			}
			fmt.Printf("Teleport %s for %s (%s).\n", status, user.email, user.id)
			return nil
		},
	}
	cmd.Flags().BoolVar(&unlock, "unlock", false, "Unlock Teleport for user")
	cmd.Flags().BoolVar(&lock, "lock", false, "Lock Teleport for user")
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
