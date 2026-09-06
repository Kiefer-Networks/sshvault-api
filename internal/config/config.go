package config

import (
	"fmt"
	"math"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	SMTP     SMTPConfig
	Vault    VaultConfig
	Rate     RateConfig
	Backup   BackupConfig
	Log      LogConfig
	Audit    AuditConfig
}

type ServerConfig struct {
	ReadTimeout       time.Duration `envconfig:"SERVER_READ_TIMEOUT" default:"120s"`
	ReadHeaderTimeout time.Duration `envconfig:"SERVER_READ_HEADER_TIMEOUT" default:"2s"`
	WriteTimeout      time.Duration `envconfig:"SERVER_WRITE_TIMEOUT" default:"180s"`
	IdleTimeout       time.Duration `envconfig:"SERVER_IDLE_TIMEOUT" default:"30s"`
	RequestTimeout    time.Duration `envconfig:"SERVER_REQUEST_TIMEOUT" default:"180s"`
	ShutdownTimeout   time.Duration `envconfig:"SERVER_SHUTDOWN_TIMEOUT" default:"30s"`
	Addr              string        `envconfig:"SERVER_ADDR" default:"127.0.0.1:8080"`
	Env               string        `envconfig:"SERVER_ENV" default:"production"`
	AppBaseURL        string        `envconfig:"APP_BASE_URL" default:"https://app.sshvault.app"`
	APIBaseURL        string        `envconfig:"API_BASE_URL" default:"https://api.sshvault.app"`
	TrustedProxies    string        `envconfig:"TRUSTED_PROXIES" default:"127.0.0.1/8,::1/128"`
	CORSOrigins       string        `envconfig:"CORS_ORIGINS"`
	ServerID          string        `envconfig:"SERVER_ID" default:"sshvault-primary"`
}

type DatabaseConfig struct {
	URL string `envconfig:"DATABASE_URL" required:"true"`
}

type JWTConfig struct {
	PrivateKeyPath string        `envconfig:"JWT_PRIVATE_KEY_PATH" default:"./keys/ed25519.pem"`
	AccessTTL      time.Duration `envconfig:"JWT_ACCESS_TTL" default:"15m"`
	RefreshTTL     time.Duration `envconfig:"JWT_REFRESH_TTL" default:"720h"`
}

type SMTPConfig struct {
	ConnectTimeout  time.Duration `envconfig:"SMTP_CONNECT_TIMEOUT" default:"10s"`
	CommandTimeout  time.Duration `envconfig:"SMTP_COMMAND_TIMEOUT" default:"10s"`
	DeliveryTimeout time.Duration `envconfig:"SMTP_DELIVERY_TIMEOUT" default:"30s"`
	Host            string        `envconfig:"SMTP_HOST"`
	Port            int           `envconfig:"SMTP_PORT" default:"587"`
	User            string        `envconfig:"SMTP_USER"`
	Pass            string        `envconfig:"SMTP_PASS"`
	From            string        `envconfig:"SMTP_FROM" default:"noreply@sshvault.app"`
}

type VaultConfig struct {
	MaxSizeMB    int `envconfig:"VAULT_MAX_SIZE_MB" default:"15"`
	HistoryLimit int `envconfig:"VAULT_HISTORY_LIMIT" default:"10"`
}

type RateConfig struct {
	RPS   float64 `envconfig:"RATE_LIMIT_RPS" default:"10"`
	Burst int     `envconfig:"RATE_LIMIT_BURST" default:"20"`
}

type BackupConfig struct {
	Dir       string        `envconfig:"BACKUP_DIR" default:"./backups"`
	Interval  time.Duration `envconfig:"BACKUP_INTERVAL" default:"24h"`
	Retention int           `envconfig:"BACKUP_RETENTION" default:"7"`
}

type LogConfig struct {
	FilePath   string `envconfig:"LOG_FILE_PATH" default:""`
	MaxSizeMB  int    `envconfig:"LOG_MAX_SIZE_MB" default:"100"`
	MaxAgeDays int    `envconfig:"LOG_MAX_AGE_DAYS" default:"90"`
	MaxBackups int    `envconfig:"LOG_MAX_BACKUPS" default:"10"`
	Compress   bool   `envconfig:"LOG_COMPRESS" default:"true"`
}

type AuditConfig struct {
	RetentionDays int `envconfig:"AUDIT_RETENTION_DAYS" default:"365"`
	BufferSize    int `envconfig:"AUDIT_BUFFER_SIZE" default:"4096"`
}

func (c *Config) IsDevelopment() bool {
	return c.Env() == "development"
}

func (c *Config) Env() string {
	return c.Server.Env
}

func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return &cfg, nil
}

// Validate runs before constructing pools, listeners, tickers, or buffered workers.
func (c *Config) Validate() error {
	for name, value := range map[string]int{"VAULT_MAX_SIZE_MB": c.Vault.MaxSizeMB, "VAULT_HISTORY_LIMIT": c.Vault.HistoryLimit, "RATE_LIMIT_BURST": c.Rate.Burst, "BACKUP_RETENTION": c.Backup.Retention, "LOG_MAX_SIZE_MB": c.Log.MaxSizeMB, "LOG_MAX_AGE_DAYS": c.Log.MaxAgeDays, "LOG_MAX_BACKUPS": c.Log.MaxBackups, "AUDIT_RETENTION_DAYS": c.Audit.RetentionDays, "AUDIT_BUFFER_SIZE": c.Audit.BufferSize} {
		if value <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	if c.Vault.MaxSizeMB > 15 {
		return fmt.Errorf("VAULT_MAX_SIZE_MB cannot exceed 15 MiB")
	}
	for name, value := range map[string]time.Duration{"SERVER_READ_TIMEOUT": c.Server.ReadTimeout, "SERVER_READ_HEADER_TIMEOUT": c.Server.ReadHeaderTimeout, "SERVER_WRITE_TIMEOUT": c.Server.WriteTimeout, "SERVER_IDLE_TIMEOUT": c.Server.IdleTimeout, "SERVER_REQUEST_TIMEOUT": c.Server.RequestTimeout, "SERVER_SHUTDOWN_TIMEOUT": c.Server.ShutdownTimeout, "SMTP_CONNECT_TIMEOUT": c.SMTP.ConnectTimeout, "SMTP_COMMAND_TIMEOUT": c.SMTP.CommandTimeout, "SMTP_DELIVERY_TIMEOUT": c.SMTP.DeliveryTimeout, "JWT_ACCESS_TTL": c.JWT.AccessTTL, "JWT_REFRESH_TTL": c.JWT.RefreshTTL, "BACKUP_INTERVAL": c.Backup.Interval} {
		if value <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	if c.Server.ReadHeaderTimeout > c.Server.ReadTimeout || c.Server.ReadTimeout > c.Server.RequestTimeout || c.Server.RequestTimeout > c.Server.WriteTimeout {
		return fmt.Errorf("HTTP timeouts must satisfy read-header <= read <= request <= write")
	}
	if c.SMTP.DeliveryTimeout < c.SMTP.ConnectTimeout || c.SMTP.DeliveryTimeout < c.SMTP.CommandTimeout {
		return fmt.Errorf("SMTP overall timeout must cover connect and command timeouts")
	}
	if c.JWT.RefreshTTL <= c.JWT.AccessTTL {
		return fmt.Errorf("JWT_REFRESH_TTL must exceed JWT_ACCESS_TTL")
	}
	if c.Rate.RPS <= 0 || math.IsNaN(c.Rate.RPS) || math.IsInf(c.Rate.RPS, 0) {
		return fmt.Errorf("RATE_LIMIT_RPS must be finite and positive")
	}
	if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
		return fmt.Errorf("SMTP_PORT must be between 1 and 65535")
	}
	if (c.SMTP.User == "") != (c.SMTP.Pass == "") {
		return fmt.Errorf("SMTP_USER and SMTP_PASS must be configured together")
	}
	if c.SMTP.Host == "" && (c.SMTP.User != "" || c.SMTP.Pass != "") {
		return fmt.Errorf("SMTP credentials require SMTP_HOST")
	}
	if c.SMTP.Host != "" && !validHost(c.SMTP.Host) {
		return fmt.Errorf("SMTP_HOST must be a hostname or IP address without scheme or port")
	}
	if address, err := mail.ParseAddress(c.SMTP.From); err != nil || address.Address != c.SMTP.From {
		return fmt.Errorf("SMTP_FROM must be a plain email address")
	}
	if _, port, err := net.SplitHostPort(c.Server.Addr); err != nil {
		return fmt.Errorf("SERVER_ADDR must be host:port")
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("SERVER_ADDR port must be between 1 and 65535")
	}
	if c.Server.Env != "production" && c.Server.Env != "development" {
		return fmt.Errorf("SERVER_ENV must be production or development")
	}
	for name, value := range map[string]string{"JWT_PRIVATE_KEY_PATH": c.JWT.PrivateKeyPath, "BACKUP_DIR": c.Backup.Dir, "SERVER_ID": c.Server.ServerID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, value := range map[string]string{"APP_BASE_URL": c.Server.AppBaseURL, "API_BASE_URL": c.Server.APIBaseURL} {
		if err := validateHTTPURL(value, false); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.Server.CORSOrigins != "" {
		for _, origin := range strings.Split(c.Server.CORSOrigins, ",") {
			if err := validateHTTPURL(strings.TrimSpace(origin), true); err != nil {
				return fmt.Errorf("CORS_ORIGINS: %w", err)
			}
		}
	}
	if c.Server.TrustedProxies != "" {
		for _, value := range strings.Split(c.Server.TrustedProxies, ",") {
			value = strings.TrimSpace(value)
			if net.ParseIP(value) != nil {
				continue
			}
			if _, _, err := net.ParseCIDR(value); err != nil {
				return fmt.Errorf("invalid TRUSTED_PROXIES entry")
			}
		}
	}
	return nil
}
func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !valid {
				return false
			}
		}
	}
	return true
}
func validateHTTPURL(raw string, origin bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid HTTP URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || !validHost(u.Hostname()) || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid URL port")
		}
	}
	if origin && u.Path != "" {
		return fmt.Errorf("CORS origin cannot include a path")
	}
	return nil
}
