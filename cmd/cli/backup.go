package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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

			path, err := createBackupWithManifest(cfg.Database.URL, dir)
			if err != nil {
				return err
			}
			fmt.Printf("Backup and manifest created: %s\n", path)
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
			fmt.Println("Only deleted accounts retained in the database or backup manifest can be preserved.")
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			ctx := context.Background()

			manifest := &restoreManifest{}
			if !skipReconcile {
				manifest, err = captureManifest(ctx, pool)
				if err != nil {
					return fmt.Errorf("pre-restore manifest: %w", err)
				}
				manifestPath := strings.TrimSuffix(file, ".sql.gz") + ".manifest.json"
				bm, loadErr := loadManifestFile(manifestPath)
				if loadErr == nil {
					manifest = mergeManifests(manifest, bm)
				} else if !errors.Is(loadErr, os.ErrNotExist) {
					return fmt.Errorf("backup manifest: %w", loadErr)
				} else {
					fmt.Println("No backup manifest found; preserving retained pre-restore tombstones only.")
				}
			}
			// Reconciliation executes before COMMIT, so any error rolls back the restore.
			if err := restoreBackup(cfg.Database.URL, file, manifest); err != nil {
				return err
			}
			fmt.Println("Restore complete. All restored access sessions, refresh tokens and verification tokens invalidated.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&skipReconcile, "no-reconcile", false, "Skip deleted-account reconciliation (tokens are still invalidated)")
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
			path, err := createBackupWithManifest(cfg.Database.URL, cfg.Backup.Dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "initial backup failed: %v\n", err)
			} else {
				fmt.Printf("[%s] Backup created: %s\n", time.Now().Format(time.RFC3339), path)
			}
			pruneBackups(cfg.Backup.Dir, cfg.Backup.Retention)

			ticker := time.NewTicker(cfg.Backup.Interval)
			defer ticker.Stop()

			for t := range ticker.C {
				path, err := createBackupWithManifest(cfg.Database.URL, cfg.Backup.Dir)
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

func createBackup(databaseURL, dir string) (path string, err error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating backup dir: %w", err)
	}
	out, err := os.CreateTemp(dir, "sshvault_"+time.Now().Format("20060102_150405")+"_*.sql.gz")
	if err != nil {
		return "", fmt.Errorf("creating backup file: %w", err)
	}
	path = out.Name()
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(out.Name())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	compressed := gzip.NewWriter(out)
	dump := exec.CommandContext(ctx, "pg_dump", "--clean", "--if-exists", "--no-owner", "--no-acl", databaseURL)
	dump.Stdout = compressed
	var stderr strings.Builder
	dump.Stderr = &stderr
	if err = dump.Run(); err != nil {
		_ = compressed.Close()
		return "", fmt.Errorf("pg_dump failed: %w\n%s", err, stderr.String())
	}
	if err = compressed.Close(); err != nil {
		return "", fmt.Errorf("compressing backup: %w", err)
	}
	if err = out.Close(); err != nil {
		return "", fmt.Errorf("closing backup: %w", err)
	}
	return path, nil
}

func createBackupWithManifest(databaseURL, dir string) (string, error) {
	manifest, err := captureManifest(context.Background(), pool)
	if err != nil {
		return "", fmt.Errorf("capturing backup manifest: %w", err)
	}
	path, err := createBackup(databaseURL, dir)
	if err != nil {
		return "", err
	}
	manifestPath := strings.TrimSuffix(path, ".sql.gz") + ".manifest.json"
	if err := writeManifestFile(manifest, manifestPath); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(manifestPath)
		return "", err
	}
	return path, nil
}

// Validate the complete compressed stream before opening a database transaction.
// Staging on disk also prevents decompression errors from committing partial SQL.
func restoreBackup(databaseURL, file string, manifest *restoreManifest) error {
	input, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("opening backup: %w", err)
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return fmt.Errorf("opening compressed backup: %w", err)
	}
	defer compressed.Close()
	staged, err := os.CreateTemp("", "sshvault-restore-*.sql")
	if err != nil {
		return fmt.Errorf("staging restore: %w", err)
	}
	defer func() { _ = staged.Close(); _ = os.Remove(staged.Name()) }()
	size, err := io.Copy(staged, compressed)
	if err != nil {
		return fmt.Errorf("validating backup: %w", err)
	}
	if size == 0 {
		return fmt.Errorf("backup SQL is empty")
	}
	if manifest != nil {
		if err := appendManifestSQL(staged, manifest); err != nil {
			return err
		}
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	psql := exec.CommandContext(ctx, "psql", "-X", "--set=ON_ERROR_STOP=on", "--single-transaction", "--file=-", databaseURL)
	psql.Stdin = staged
	var stderr strings.Builder
	psql.Stderr = &stderr
	if err := psql.Run(); err != nil {
		return fmt.Errorf("psql restore failed: %w\n%s", err, stderr.String())
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
			_ = os.Remove(strings.TrimSuffix(path, ".sql.gz") + ".manifest.json")
			fmt.Printf("  Pruned old backup: %s\n", e.Name())
		}
	}
}
