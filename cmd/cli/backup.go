package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
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

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			err = repository.WithExclusiveMaintenance(ctx, pool, func(connection *pgx.Conn) error {
				manifest := &restoreManifest{}
				if !skipReconcile {
					bm, err := loadManifestFile(strings.TrimSuffix(file, ".sql.gz") + ".manifest.json")
					if err != nil {
						return fmt.Errorf("backup manifest (use --no-reconcile only to explicitly override): %w", err)
					}
					live, err := captureManifest(ctx, connection)
					if err != nil {
						return fmt.Errorf("pre-restore manifest: %w", err)
					}
					manifest = mergeManifests(live, bm)
					manifest.FormatVersion, manifest.DumpSHA256 = bm.FormatVersion, bm.DumpSHA256
				}
				// The exclusive lock survives until psql commits reconciliation.
				return restoreBackupContext(ctx, cfg.Database.URL, file, manifest)
			})
			if err != nil {
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

// A staged dump is never listed or pruned as a completed backup.
func dumpBackup(ctx context.Context, databaseURL, dir, snapshot string) (path string, err error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating backup dir: %w", err)
	}
	out, err := os.CreateTemp(dir, "sshvault_"+time.Now().Format("20060102_150405")+"_*.sql.gz.partial")
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
	compressed := gzip.NewWriter(out)
	args := []string{"--clean", "--if-exists", "--no-owner", "--no-acl"}
	if snapshot != "" {
		args = append(args, "--snapshot", snapshot)
	}
	dump, err := postgresCommand(ctx, "pg_dump", databaseURL, args...)
	if err != nil {
		_ = compressed.Close()
		return "", err
	}
	dump.Stdout = compressed
	if err = dump.Run(); err != nil {
		_ = compressed.Close()
		return "", fmt.Errorf("pg_dump failed: %w", err)
	}
	if err = compressed.Close(); err != nil {
		return "", fmt.Errorf("compressing backup: %w", err)
	}
	if err = out.Sync(); err != nil {
		return "", fmt.Errorf("flushing backup: %w", err)
	}
	if err = out.Close(); err != nil {
		return "", fmt.Errorf("closing backup: %w", err)
	}
	return path, nil
}

func createBackupWithManifest(databaseURL, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var path string
	err := repository.WithSharedMaintenance(ctx, pool, func(connection *pgx.Conn) error {
		var err error
		path, err = createSnapshotBackup(ctx, connection, databaseURL, dir)
		return err
	})
	return path, err
}

func createSnapshotBackup(ctx context.Context, connection *pgx.Conn, databaseURL, dir string) (string, error) {
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var snapshot string
	if err = tx.QueryRow(ctx, "SELECT pg_export_snapshot()").Scan(&snapshot); err != nil {
		return "", fmt.Errorf("exporting backup snapshot: %w", err)
	}
	manifest, err := captureManifest(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("capturing backup manifest: %w", err)
	}
	staged, err := dumpBackup(ctx, databaseURL, dir, snapshot)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(staged) }()
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	manifest.FormatVersion = 1
	manifest.DumpSHA256, err = backupDigest(staged)
	if err != nil {
		return "", err
	}
	final := strings.TrimSuffix(staged, ".partial")
	sidecar := strings.TrimSuffix(final, ".sql.gz") + ".manifest.json"
	stagedSidecar := sidecar + ".partial"
	defer func() { _ = os.Remove(stagedSidecar) }()
	if err := writeManifestFile(manifest, stagedSidecar); err != nil {
		return "", err
	}
	// Publish the sidecar first: a visible .sql.gz always has its durable sidecar.
	if err := os.Rename(stagedSidecar, sidecar); err != nil {
		return "", err
	}
	if err := os.Rename(staged, final); err != nil {
		_ = os.Remove(sidecar)
		return "", err
	}
	return final, nil
}

func backupDigest(path string) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = input.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, input); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func restoreBackupContext(ctx context.Context, databaseURL, file string, manifest *restoreManifest) error {
	input, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("opening backup: %w", err)
	}
	defer func() { _ = input.Close() }()
	hash := sha256.New()
	compressed, err := gzip.NewReader(io.TeeReader(input, hash))
	if err != nil {
		return fmt.Errorf("opening compressed backup: %w", err)
	}
	defer func() { _ = compressed.Close() }()
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
	// Hash exactly the compressed bytes staged for psql, avoiding a verify/reopen
	// race if the backup path changes while restore is being prepared.
	if manifest != nil && manifest.FormatVersion != 0 && hex.EncodeToString(hash.Sum(nil)) != manifest.DumpSHA256 {
		return fmt.Errorf("backup digest does not match manifest (use --no-reconcile only to explicitly override)")
	}
	if manifest != nil {
		if err := appendManifestSQL(staged, manifest); err != nil {
			return err
		}
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	psql, err := postgresCommand(ctx, "psql", databaseURL, "-X", "--set=ON_ERROR_STOP=on", "--single-transaction", "--file=-")
	if err != nil {
		return err
	}
	psql.Stdin = staged
	if err := psql.Run(); err != nil {
		return fmt.Errorf("psql restore failed: %w", err)
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
