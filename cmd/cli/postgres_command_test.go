package main

import (
	"context"
	"strings"
	"testing"
)

func TestPostgresCommandPreservesConnectionOptionsWithoutCredentials(t *testing.T) {
	t.Setenv("PGUSER", "inherited")
	t.Setenv("PGPASSWORD", "inherited-secret")
	for _, name := range []string{"pg_dump", "psql"} {
		t.Run(name, func(t *testing.T) {
			command, err := postgresCommand(context.Background(), name, "postgresql://ignored:ignored-secret@localhost/test?sslmode=verify-full&application_name=backup&user=effective&password=encoded%26secret", "--help")
			if err != nil {
				t.Fatal(err)
			}
			args := strings.Join(command.Args, " ")
			for _, credential := range []string{"ignored", "effective", "secret", "encoded"} {
				if strings.Contains(args, credential) {
					t.Error("credentials leaked into child argv")
				}
			}
			if !strings.Contains(args, "sslmode=verify-full") || !strings.Contains(args, "application_name=backup") {
				t.Error("connection options were lost")
			}
			values := map[string][]string{}
			for _, entry := range command.Env {
				key, value, _ := strings.Cut(entry, "=")
				values[key] = append(values[key], value)
			}
			if got := values["PGUSER"]; len(got) != 1 || got[0] != "effective" {
				t.Error("effective user was not passed exclusively via environment")
			}
			if got := values["PGPASSWORD"]; len(got) != 1 || got[0] != "encoded&secret" {
				t.Error("effective decoded password was not passed exclusively via environment")
			}
		})
	}
}

func TestPostgresCommandParseErrorDoesNotEchoSecret(t *testing.T) {
	_, err := postgresCommand(context.Background(), "psql", "postgresql://user:secret@host/%invalid")
	if err == nil {
		t.Fatal("invalid URL accepted")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("parse error echoed credentials")
	}
}

func TestPostgresCommandAcceptsExistingKeywordConnectionStrings(t *testing.T) {
	command, err := postgresCommand(context.Background(), "psql", `host=localhost port=5432 dbname='database name' user='first' user='operator name' password='quote\' and slash\\ secret' sslmode=require`)
	if err != nil {
		t.Fatalf("existing libpq connection string rejected: %v", err)
	}
	args := strings.Join(command.Args, " ")
	if strings.Contains(args, "operator") || strings.Contains(args, "secret") || strings.Contains(args, "first") {
		t.Fatal("keyword credentials remain in argv")
	}
	if !strings.Contains(args, "sslmode=require") || !strings.Contains(args, "dbname='database name'") {
		t.Fatal("non-credential connection options changed")
	}
	env := map[string]string{}
	for _, entry := range command.Env {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	if env["PGUSER"] != "operator name" || env["PGPASSWORD"] != "quote' and slash\\ secret" {
		t.Fatal("quoted keyword credentials were not preserved")
	}
}
