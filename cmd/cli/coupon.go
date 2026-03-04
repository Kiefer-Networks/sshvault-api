package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func couponCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coupon",
		Short: "Coupon management",
	}

	cmd.AddCommand(couponCreateCmd())
	cmd.AddCommand(couponListCmd())
	cmd.AddCommand(couponInfoCmd())
	cmd.AddCommand(couponRevokeCmd())

	return cmd
}

func couponCreateCmd() *cobra.Command {
	var (
		code     string
		gSync    bool
		days     int
		gTele    bool
		maxUses  int
		expires  string
		note     string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new coupon code",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !gSync && !gTele {
				return fmt.Errorf("specify at least --sync or --teleport")
			}

			if code == "" {
				b := make([]byte, 4)
				if _, err := rand.Read(b); err != nil {
					return fmt.Errorf("generating code: %w", err)
				}
				code = strings.ToUpper(hex.EncodeToString(b))
			}

			ctx := context.Background()

			var expiresAt *time.Time
			if expires != "" {
				t, err := time.Parse("2006-01-02", expires)
				if err != nil {
					return fmt.Errorf("invalid expires date (use YYYY-MM-DD): %w", err)
				}
				// Set to end of day UTC.
				eod := t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
				expiresAt = &eod
			}

			_, err := pool.Exec(ctx, `
				INSERT INTO coupons (code, grant_sync, grant_teleport, sync_days, max_uses, expires_at, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				code, gSync, gTele, days, maxUses, expiresAt, note)
			if err != nil {
				return fmt.Errorf("creating coupon: %w", err)
			}

			fmt.Printf("Coupon created:\n")
			fmt.Printf("  Code:       %s\n", code)
			fmt.Printf("  Sync:       %v", gSync)
			if gSync {
				fmt.Printf(" (%d days)", days)
			}
			fmt.Println()
			fmt.Printf("  Teleport:   %v\n", gTele)
			fmt.Printf("  Max Uses:   %d\n", maxUses)
			if expiresAt != nil {
				fmt.Printf("  Expires:    %s\n", expiresAt.Format("2006-01-02"))
			} else {
				fmt.Printf("  Expires:    never\n")
			}
			if note != "" {
				fmt.Printf("  Note:       %s\n", note)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&code, "code", "", "Coupon code (auto-generated if empty)")
	cmd.Flags().BoolVar(&gSync, "sync", false, "Grant sync subscription")
	cmd.Flags().IntVar(&days, "days", 365, "Sync subscription duration in days")
	cmd.Flags().BoolVar(&gTele, "teleport", false, "Grant Teleport addon")
	cmd.Flags().IntVar(&maxUses, "uses", 1, "Maximum number of redemptions")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiration date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&note, "note", "", "Admin note (created_by)")

	return cmd
}

func couponListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all coupons",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			rows, err := pool.Query(ctx, `
				SELECT code, grant_sync, grant_teleport, sync_days, max_uses, used_count, expires_at, created_at, created_by
				FROM coupons ORDER BY created_at DESC`)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			fmt.Printf("%-12s  %-6s  %-8s  %-5s  %-10s  %-12s  %-20s  %s\n",
				"CODE", "SYNC", "TELEPORT", "DAYS", "USES", "EXPIRES", "CREATED", "NOTE")
			fmt.Println(strings.Repeat("─", 110))

			count := 0
			for rows.Next() {
				var (
					c          string
					gSync      bool
					gTele      bool
					syncDays   int
					maxUses    int
					usedCount  int
					expiresAt  *time.Time
					createdAt  time.Time
					createdBy  string
				)
				if err := rows.Scan(&c, &gSync, &gTele, &syncDays, &maxUses, &usedCount, &expiresAt, &createdAt, &createdBy); err != nil {
					return fmt.Errorf("scan: %w", err)
				}

				expStr := "never"
				if expiresAt != nil {
					expStr = expiresAt.Format("2006-01-02")
					if time.Now().After(*expiresAt) {
						expStr += " !"
					}
				}

				usesStr := fmt.Sprintf("%d/%d", usedCount, maxUses)

				fmt.Printf("%-12s  %-6v  %-8v  %-5d  %-10s  %-12s  %-20s  %s\n",
					c, gSync, gTele, syncDays, usesStr, expStr,
					createdAt.Format("2006-01-02 15:04"), truncate(createdBy, 20))
				count++
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterating rows: %w", err)
			}
			fmt.Printf("\nTotal: %d coupon(s)\n", count)
			return nil
		},
	}
}

func couponInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <code>",
		Short: "Show coupon details and redemptions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			code := args[0]

			var (
				id         string
				gSync      bool
				gTele      bool
				syncDays   int
				maxUses    int
				usedCount  int
				expiresAt  *time.Time
				createdAt  time.Time
				createdBy  string
			)
			err := pool.QueryRow(ctx, `
				SELECT id, grant_sync, grant_teleport, sync_days, max_uses, used_count, expires_at, created_at, created_by
				FROM coupons WHERE code = $1`, code).
				Scan(&id, &gSync, &gTele, &syncDays, &maxUses, &usedCount, &expiresAt, &createdAt, &createdBy)
			if err != nil {
				return fmt.Errorf("coupon not found: %s", code)
			}

			fmt.Printf("ID:         %s\n", id)
			fmt.Printf("Code:       %s\n", code)
			fmt.Printf("Sync:       %v\n", gSync)
			if gSync {
				fmt.Printf("  Days:     %d\n", syncDays)
			}
			fmt.Printf("Teleport:   %v\n", gTele)
			fmt.Printf("Uses:       %d / %d\n", usedCount, maxUses)
			if expiresAt != nil {
				expStr := expiresAt.Format("2006-01-02 15:04")
				if time.Now().After(*expiresAt) {
					expStr += " (EXPIRED)"
				}
				fmt.Printf("Expires:    %s\n", expStr)
			} else {
				fmt.Printf("Expires:    never\n")
			}
			fmt.Printf("Created:    %s\n", createdAt.Format(time.RFC3339))
			if createdBy != "" {
				fmt.Printf("Note:       %s\n", createdBy)
			}

			// Redemptions
			rRows, err := pool.Query(ctx, `
				SELECT cr.user_id, u.email, cr.redeemed_at
				FROM coupon_redemptions cr
				JOIN users u ON u.id = cr.user_id
				WHERE cr.coupon_id = $1
				ORDER BY cr.redeemed_at DESC`, id)
			if err == nil {
				defer rRows.Close()
				fmt.Println("\nRedemptions:")
				hasRows := false
				for rRows.Next() {
					var uid, email string
					var redeemedAt time.Time
					if err := rRows.Scan(&uid, &email, &redeemedAt); err != nil {
						continue
					}
					fmt.Printf("  - %s (%s) at %s\n", email, uid, redeemedAt.Format("2006-01-02 15:04"))
					hasRows = true
				}
				if err := rRows.Err(); err != nil {
					return fmt.Errorf("iterating redemption rows: %w", err)
				}
				if !hasRows {
					fmt.Println("  (none)")
				}
			}

			return nil
		},
	}
}

func couponRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <code>",
		Short: "Delete a coupon (prevents future redemptions)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			code := args[0]

			fmt.Printf("Revoke coupon %s? This prevents future redemptions.\n", code)
			if !confirm() {
				fmt.Println("Aborted.")
				return nil
			}

			result, err := pool.Exec(ctx, `DELETE FROM coupons WHERE code = $1`, code)
			if err != nil {
				return fmt.Errorf("deleting coupon: %w", err)
			}
			if result.RowsAffected() == 0 {
				return fmt.Errorf("coupon not found: %s", code)
			}
			fmt.Printf("Coupon %s revoked (deleted).\n", code)
			return nil
		},
	}
}
