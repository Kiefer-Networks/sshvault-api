package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/kiefernetworks/shellvault-server/internal/config"
)

var pool *pgxpool.Pool

func main() {
	root := &cobra.Command{
		Use:   "sshvault-cli",
		Short: "SSHVault Server Admin CLI",
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
	root.AddCommand(backupCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
