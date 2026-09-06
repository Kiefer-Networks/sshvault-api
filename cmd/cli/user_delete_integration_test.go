package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestCLIHardDeleteAnonymizesOrRollsBack(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "anonymization_failure"}[failure], func(t *testing.T) {
			p := testutil.Database(t, 0)
			previous := pool
			pool = p
			defer func() { pool = previous }()
			uid := uuid.New()
			testutil.Exec(t, p, `INSERT INTO users(id,email,password) VALUES($1,'delete@example.com','test')`, uid)
			testutil.Exec(t, p, `INSERT INTO devices(user_id,name,platform) VALUES($1,'laptop','linux')`, uid)
			testutil.Exec(t, p, `INSERT INTO audit_logs(category,action,actor_id,actor_email) VALUES('auth','login',$1,'delete@example.com')`, uid)
			testutil.Exec(t, p, `INSERT INTO login_attempts(email,ip_address,success) VALUES('delete@example.com','hash',FALSE)`)
			if failure {
				testutil.Exec(t, p, `CREATE OR REPLACE FUNCTION audit_anonymize_user(target_user_id uuid) RETURNS int AS $$ BEGIN RAISE EXCEPTION 'injected anonymization failure'; END $$ LANGUAGE plpgsql`)
			}
			input, err := os.CreateTemp(t.TempDir(), "confirmation")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close() }()
			if _, err = input.WriteString("yes\n"); err != nil {
				t.Fatal(err)
			}
			if _, err = input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			oldInput := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = oldInput }()
			cmd := userDeleteCmd()
			cmd.SetArgs([]string{uid.String(), "--hard"})
			err = cmd.Execute()
			if (err != nil) != failure {
				t.Fatalf("hard delete err=%v failure=%v", err, failure)
			}
			want := 0
			if failure {
				want = 1
			}
			for _, table := range []string{"users", "devices", "login_attempts"} {
				var count int
				if err := p.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != want {
					t.Errorf("%s rows=%d want=%d", table, count, want)
				}
			}
			var identifiable int
			if err := p.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE actor_id IS NOT NULL OR actor_email<>''`).Scan(&identifiable); err != nil {
				t.Fatal(err)
			}
			if identifiable != want {
				t.Errorf("identifiable audit rows=%d want=%d", identifiable, want)
			}
		})
	}
}
