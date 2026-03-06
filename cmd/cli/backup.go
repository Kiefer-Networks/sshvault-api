package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/kiefernetworks/shellvault-server/internal/config"
)

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
			fmt.Printf("Manifest created: %s (%d deleted users, %d revoked tokens)\n",
				manifestPath, len(manifest.DeletedUsers), manifest.RevokedTokenCount)
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
			fmt.Println("Deleted accounts will be preserved.")
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			ctx := context.Background()

			// Step 1: Pre-restore snapshot
			fmt.Println("\n[1/4] Capturing pre-restore manifest...")
			preManifest, err := captureManifest(ctx, pool)
			if err != nil {
				return fmt.Errorf("pre-restore manifest: %w", err)
			}
			fmt.Printf("  Captured: %d deleted users, %d revoked tokens\n",
				len(preManifest.DeletedUsers), preManifest.RevokedTokenCount)

			// Step 2: Restore SQL dump
			fmt.Println("\n[2/4] Restoring database...")
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
			fmt.Println("\n[3/4] Loading backup manifest...")
			var backupManifest *restoreManifest
			manifestPath := strings.TrimSuffix(file, ".sql.gz") + ".manifest.json"
			if bm, err := loadManifestFile(manifestPath); err == nil {
				backupManifest = bm
				fmt.Printf("  Loaded: %d deleted users\n",
					len(bm.DeletedUsers))
			} else {
				fmt.Println("  No backup manifest found, using pre-restore snapshot only.")
			}

			// Step 4: Merge and apply
			fmt.Println("\n[4/4] Applying reconciliation...")
			merged := preManifest
			if backupManifest != nil {
				merged = mergeManifests(preManifest, backupManifest)
			}
			deletedUsers, revokedTokens := applyManifest(ctx, pool, merged)
			fmt.Printf("  Re-deleted %d user(s), re-revoked %d token(s)\n",
				deletedUsers, revokedTokens)

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
	filename := fmt.Sprintf("sshvault_%s.sql.gz", timestamp)
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
	fmt.Printf("  Manifest: %d deleted users\n",
		len(manifest.DeletedUsers))
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
