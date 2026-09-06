package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Keep credentials out of argv. Retain libpq connection options (including TLS)
// and pass only user/password via their supported environment. Child stderr is
// not attached because errors may echo credentials or SQL backup contents.
func postgresCommand(ctx context.Context, name, databaseURL string, args ...string) (*exec.Cmd, error) {
	connection, credentials, err := postgresConnection(databaseURL)
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	for key, value := range credentials {
		prefix := key + "="
		filtered := env[:0]
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, prefix+value)
	}
	args = append(args, "--dbname", connection)
	command := exec.CommandContext(ctx, name, args...)
	command.Env = env
	return command, nil
}

func postgresConnection(value string) (string, map[string]string, error) {
	credentials := map[string]string{}
	invalid := func() (string, map[string]string, error) {
		return "", nil, fmt.Errorf("invalid PostgreSQL connection configuration")
	}
	if strings.HasPrefix(value, "postgres://") || strings.HasPrefix(value, "postgresql://") {
		connection, err := url.Parse(value)
		if err != nil {
			return invalid()
		}
		if connection.User != nil {
			credentials["PGUSER"] = connection.User.Username()
			if password, ok := connection.User.Password(); ok {
				credentials["PGPASSWORD"] = password
			}
			connection.User = nil
		}
		query, err := url.ParseQuery(connection.RawQuery)
		if err != nil {
			return invalid()
		}
		for key, environment := range map[string]string{"user": "PGUSER", "password": "PGPASSWORD"} {
			if query.Has(key) {
				credentials[environment] = query.Get(key)
				query.Del(key)
			}
		}
		connection.RawQuery = query.Encode()
		return connection.String(), credentials, nil
	}
	// libpq also accepts keyword/value DSNs. Preserve each non-credential field
	// verbatim, decoding quoted/backslash-escaped credentials only for environment.
	var fields []string
	space := func(c byte) bool { return strings.ContainsRune(" \t\r\n\v\f", rune(c)) }
	for i := 0; i < len(value); {
		for i < len(value) && space(value[i]) {
			i++
		}
		if i == len(value) {
			break
		}
		start := i
		for i < len(value) && !space(value[i]) && value[i] != '=' {
			i++
		}
		key := value[start:i]
		for i < len(value) && space(value[i]) {
			i++
		}
		if key == "" || i == len(value) || value[i] != '=' {
			return invalid()
		}
		i++
		for i < len(value) && space(value[i]) {
			i++
		}
		quoted := i < len(value) && value[i] == '\''
		if quoted {
			i++
		}
		closed := !quoted
		var decoded strings.Builder
		for i < len(value) {
			c := value[i]
			if c == '\\' {
				i++
				if i == len(value) {
					return invalid()
				}
				decoded.WriteByte(value[i])
				i++
				continue
			}
			if quoted && c == '\'' {
				i++
				closed = true
				break
			}
			if !quoted && space(c) {
				break
			}
			decoded.WriteByte(c)
			i++
		}
		if !closed {
			return invalid()
		}
		switch key {
		case "user":
			credentials["PGUSER"] = decoded.String()
		case "password":
			credentials["PGPASSWORD"] = decoded.String()
		default:
			fields = append(fields, value[start:i])
		}
	}
	if len(fields) == 0 && len(credentials) == 0 {
		return invalid()
	}
	return strings.Join(fields, " "), credentials, nil
}
