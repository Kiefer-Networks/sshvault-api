package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/kiefernetworks/shellvault-server/internal/config"
)

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

			// OAuth accounts
			oauthRows, err := pool.Query(ctx,
				`SELECT provider, provider_id, email FROM oauth_accounts WHERE user_id = $1`, user.id)
			if err == nil {
				defer oauthRows.Close()
				fmt.Println("\nOAuth Accounts:")
				hasOAuth := false
				for oauthRows.Next() {
					var provider, providerID, oaEmail string
					if err := oauthRows.Scan(&provider, &providerID, &oaEmail); err != nil {
						continue
					}
					fmt.Printf("  - %s: %s (%s)\n", provider, providerID, oaEmail)
					hasOAuth = true
				}
				if err := oauthRows.Err(); err != nil {
					return fmt.Errorf("iterating oauth rows: %w", err)
				}
				if !hasOAuth {
					fmt.Println("  (none)")
				}
			}

			// Subscription
			var subProvider, subStatus string
			var periodEnd *time.Time
			err = pool.QueryRow(ctx,
				`SELECT provider, status, current_period_end FROM subscriptions
				 WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, user.id).
				Scan(&subProvider, &subStatus, &periodEnd)
			fmt.Println("\nSubscription:")
			if err != nil {
				fmt.Println("  (none)")
			} else {
				fmt.Printf("  Provider: %s\n", subProvider)
				fmt.Printf("  Status:   %s\n", subStatus)
				if periodEnd != nil {
					fmt.Printf("  Expires:  %s\n", periodEnd.Format(time.RFC3339))
				}
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
		Short: "Revoke all subscriptions for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			user, err := findUser(ctx, args[0])
			if err != nil {
				return err
			}

			result, err := pool.Exec(ctx,
				`UPDATE subscriptions SET status = 'canceled', updated_at = now() WHERE user_id = $1`,
				user.id)
			if err != nil {
				return fmt.Errorf("revoke: %w", err)
			}

			fmt.Printf("Revoked %d subscription(s) for %s.\n", result.RowsAffected(), user.email)
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
		Short: "Create a database backup (pg_dump)",
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
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output directory (default from BACKUP_DIR)")
	return cmd
}

func backupRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <file>",
		Short: "Restore database from a backup file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			file := args[0]

			fmt.Printf("RESTORE database from %s?\n", file)
			fmt.Println("WARNING: This will overwrite the current database!")
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			if err := restoreBackup(cfg.Database.URL, file); err != nil {
				return err
			}
			fmt.Println("Database restored successfully.")
			return nil
		},
	}
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
