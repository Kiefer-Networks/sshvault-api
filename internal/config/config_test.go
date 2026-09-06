package config

import (
	"testing"
)

func TestLoadRejectsInvalidRuntimeConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test?sslmode=disable")
	for _, tc := range []struct{ key, value string }{
		{"SERVER_READ_TIMEOUT", "0s"}, {"SERVER_READ_HEADER_TIMEOUT", "0s"}, {"SERVER_WRITE_TIMEOUT", "0s"}, {"SERVER_IDLE_TIMEOUT", "0s"}, {"SERVER_REQUEST_TIMEOUT", "0s"}, {"SERVER_SHUTDOWN_TIMEOUT", "0s"}, {"SERVER_READ_HEADER_TIMEOUT", "3m"}, {"SERVER_REQUEST_TIMEOUT", "4m"}, {"SMTP_CONNECT_TIMEOUT", "0s"}, {"SMTP_COMMAND_TIMEOUT", "0s"}, {"SMTP_DELIVERY_TIMEOUT", "0s"}, {"SMTP_DELIVERY_TIMEOUT", "1s"}, {"JWT_ACCESS_TTL", "0s"}, {"JWT_REFRESH_TTL", "-1s"}, {"JWT_REFRESH_TTL", "1m"}, {"BACKUP_INTERVAL", "0s"},
		{"VAULT_MAX_SIZE_MB", "0"}, {"VAULT_MAX_SIZE_MB", "16"}, {"VAULT_HISTORY_LIMIT", "-1"}, {"RATE_LIMIT_RPS", "0"}, {"RATE_LIMIT_RPS", "NaN"}, {"RATE_LIMIT_RPS", "+Inf"}, {"RATE_LIMIT_BURST", "0"},
		{"BACKUP_RETENTION", "0"}, {"LOG_MAX_SIZE_MB", "0"}, {"LOG_MAX_AGE_DAYS", "0"}, {"LOG_MAX_BACKUPS", "-1"}, {"AUDIT_RETENTION_DAYS", "0"}, {"AUDIT_BUFFER_SIZE", "0"},
		{"SMTP_PORT", "0"}, {"SMTP_PORT", "65536"}, {"SMTP_HOST", "https://mail.example.com"}, {"SMTP_USER", "user-without-host"},
		{"APP_BASE_URL", "javascript:alert(1)"}, {"API_BASE_URL", "/relative"}, {"API_BASE_URL", "https://user:pass@example.com"}, {"CORS_ORIGINS", "https://example.com/path"},
		{"TRUSTED_PROXIES", "10.0.0.0/33"}, {"TRUSTED_PROXIES", "127.0.0.1,,::1"}, {"SERVER_ADDR", "localhost:0"}, {"SERVER_ENV", "typo"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
func TestDefaultVaultLimitIs15MiB(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.MaxSizeMB != 15 {
		t.Fatalf("vault default = %d MiB", cfg.Vault.MaxSizeMB)
	}
}
