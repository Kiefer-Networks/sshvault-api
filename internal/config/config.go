package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
	SMTP     SMTPConfig
	Billing  BillingConfig
	Vault    VaultConfig
	Rate     RateConfig
	Backup   BackupConfig
}

type ServerConfig struct {
	Addr           string `envconfig:"SERVER_ADDR" default:"127.0.0.1:8080"`
	Env            string `envconfig:"SERVER_ENV" default:"production"`
	AppBaseURL     string `envconfig:"APP_BASE_URL" default:"https://app.sshvault.app"`
	APIBaseURL     string `envconfig:"API_BASE_URL" default:"https://api.sshvault.app"`
	TrustedProxies string `envconfig:"TRUSTED_PROXIES" default:"127.0.0.1/8,::1/128"`
	CORSOrigins    string `envconfig:"CORS_ORIGINS"`
}

type DatabaseConfig struct {
	URL string `envconfig:"DATABASE_URL" required:"true"`
}

type JWTConfig struct {
	PrivateKeyPath string        `envconfig:"JWT_PRIVATE_KEY_PATH" default:"./keys/ed25519.pem"`
	AccessTTL      time.Duration `envconfig:"JWT_ACCESS_TTL" default:"15m"`
	RefreshTTL     time.Duration `envconfig:"JWT_REFRESH_TTL" default:"720h"`
}

type OAuthConfig struct {
	AppleTeamID    string `envconfig:"OAUTH_APPLE_TEAM_ID"`
	AppleClientID  string `envconfig:"OAUTH_APPLE_CLIENT_ID"`
	AppleKeyID     string `envconfig:"OAUTH_APPLE_KEY_ID"`
	AppleKeyPath   string `envconfig:"OAUTH_APPLE_KEY_PATH"`
	GoogleClientID string `envconfig:"OAUTH_GOOGLE_CLIENT_ID"`
}

type SMTPConfig struct {
	Host string `envconfig:"SMTP_HOST"`
	Port int    `envconfig:"SMTP_PORT" default:"587"`
	User string `envconfig:"SMTP_USER"`
	Pass string `envconfig:"SMTP_PASS"`
	From string `envconfig:"SMTP_FROM" default:"noreply@sshvault.app"`
}

type BillingConfig struct {
	StripeSecretKey        string `envconfig:"STRIPE_SECRET_KEY"`
	StripeWebhookSecret    string `envconfig:"STRIPE_WEBHOOK_SECRET"`
	StripePriceID          string `envconfig:"STRIPE_PRICE_ID"`
	AppleSharedSecret      string `envconfig:"APPLE_SHARED_SECRET"`
	GoogleServiceAcctPath  string `envconfig:"GOOGLE_SERVICE_ACCOUNT_PATH"`
}

type VaultConfig struct {
	MaxSizeMB    int `envconfig:"VAULT_MAX_SIZE_MB" default:"50"`
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

func (c *Config) IsDevelopment() bool {
	return c.Env() == "development"
}

func (c *Config) Env() string {
	return c.Server.Env
}

func (c *BillingConfig) Enabled() bool {
	return c.StripeSecretKey != ""
}

func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return &cfg, nil
}
