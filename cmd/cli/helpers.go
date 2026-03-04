package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
