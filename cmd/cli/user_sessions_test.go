package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAdministrativeSessionChangesRevokeAllTokens(t *testing.T) {
	for _, state := range []string{"logout", "deactivate", "activate"} {
		t.Run(state, func(t *testing.T) {
			p, _ := backupTestDB(t)
			execSQL(t, p, `CREATE TABLE users(id uuid PRIMARY KEY,session_version bigint NOT NULL,deleted_at timestamptz,updated_at timestamptz); CREATE TABLE refresh_tokens(user_id uuid,revoked boolean);`)
			uid := uuid.New()
			if _, err := p.Exec(context.Background(), `INSERT INTO users VALUES($1,4,NULL,now());`, uid); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(context.Background(), `INSERT INTO refresh_tokens VALUES($1,FALSE);`, uid); err != nil {
				t.Fatal(err)
			}
			previous := pool
			pool = p
			t.Cleanup(func() { pool = previous })
			count, err := updateUserSessions(context.Background(), uid, state)
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("revoked=%d", count)
			}
			var version int64
			var deleted, revoked bool
			if err := p.QueryRow(context.Background(), `SELECT session_version,deleted_at IS NOT NULL FROM users WHERE id=$1`, uid).Scan(&version, &deleted); err != nil {
				t.Fatal(err)
			}
			if err := p.QueryRow(context.Background(), `SELECT revoked FROM refresh_tokens WHERE user_id=$1`, uid).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if version != 5 || deleted != (state == "deactivate") || !revoked {
				t.Fatalf("version=%d deleted=%v revoked=%v", version, deleted, revoked)
			}
		})
	}
}

func TestAdministrativeRevocationRollsBackUserOnTokenFailure(t *testing.T) {
	p, _ := backupTestDB(t)
	execSQL(t, p, `CREATE TABLE users(id uuid PRIMARY KEY,session_version bigint NOT NULL,deleted_at timestamptz,updated_at timestamptz); CREATE TABLE refresh_tokens(user_id uuid,revoked boolean CHECK(NOT revoked));`)
	uid := uuid.New()
	if _, err := p.Exec(context.Background(), `INSERT INTO users VALUES($1,4,NULL,now());`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(context.Background(), `INSERT INTO refresh_tokens VALUES($1,FALSE);`, uid); err != nil {
		t.Fatal(err)
	}
	previous := pool
	pool = p
	t.Cleanup(func() { pool = previous })
	if _, err := updateUserSessions(context.Background(), uid, "deactivate"); err == nil {
		t.Fatal("expected token update failure")
	}
	var version int64
	var deleted bool
	if err := p.QueryRow(context.Background(), `SELECT session_version,deleted_at IS NOT NULL FROM users WHERE id=$1`, uid).Scan(&version, &deleted); err != nil {
		t.Fatal(err)
	}
	if version != 4 || deleted {
		t.Fatalf("partial change persisted: version=%d deleted=%v", version, deleted)
	}
}
