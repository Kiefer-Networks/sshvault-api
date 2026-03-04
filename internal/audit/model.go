package audit

import (
	"time"

	"github.com/google/uuid"
)

// Level represents the severity of an audit event.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Category groups audit events by domain area.
type Category string

const (
	CatAuth    Category = "AUTH"
	CatVault   Category = "VAULT"
	CatBilling Category = "BILLING"
	CatDevice  Category = "DEVICE"
	CatUser    Category = "USER"
	CatSystem  Category = "SYSTEM"
	CatWebhook  Category = "WEBHOOK"
	CatTeleport Category = "TELEPORT"
)

// Action describes the specific operation that was performed.
type Action string

const (
	// Auth actions
	ActRegister      Action = "REGISTER"
	ActLogin         Action = "LOGIN"
	ActLoginFailed   Action = "LOGIN_FAILED"
	ActRefreshToken  Action = "REFRESH_TOKEN"
	ActLogout        Action = "LOGOUT"
	ActLogoutAll     Action = "LOGOUT_ALL"
	ActVerifyEmail   Action = "VERIFY_EMAIL"
	ActForgotPassword Action = "FORGOT_PASSWORD"
	ActResetPassword Action = "RESET_PASSWORD"

	// Vault actions
	ActSyncPull    Action = "SYNC_PULL"
	ActSyncPush    Action = "SYNC_PUSH"
	ActHistoryView Action = "HISTORY_VIEW"

	// User actions
	ActProfileView   Action = "PROFILE_VIEW"
	ActProfileUpdate Action = "PROFILE_UPDATE"
	ActPasswordChange Action = "PASSWORD_CHANGE"
	ActAccountDelete Action = "ACCOUNT_DELETE"

	// Device actions
	ActDeviceRegister Action = "DEVICE_REGISTER"
	ActDeviceList     Action = "DEVICE_LIST"
	ActDeviceDelete   Action = "DEVICE_DELETE"

	// Billing actions
	ActStatusCheck   Action = "STATUS_CHECK"
	ActCheckout      Action = "CHECKOUT"
	ActPortal        Action = "PORTAL"
	ActWebhookStripe Action = "WEBHOOK_STRIPE"
	ActWebhookApple  Action = "WEBHOOK_APPLE"
	ActWebhookGoogle Action = "WEBHOOK_GOOGLE"

	// Teleport actions
	ActClusterRegister Action = "CLUSTER_REGISTER"
	ActClusterList     Action = "CLUSTER_LIST"
	ActClusterDelete   Action = "CLUSTER_DELETE"
	ActTeleportLogin   Action = "TELEPORT_LOGIN"
	ActNodeList        Action = "NODE_LIST"
	ActCertGenerate    Action = "CERT_GENERATE"

	// System actions
	ActStartup  Action = "STARTUP"
	ActShutdown Action = "SHUTDOWN"
)

// Entry represents a single audit log record.
type Entry struct {
	ID           uuid.UUID              `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Level        Level                  `json:"level"`
	Category     Category               `json:"category"`
	Action       Action                 `json:"action"`
	ActorID      *uuid.UUID             `json:"actor_id,omitempty"`
	ActorEmail   string                 `json:"actor_email,omitempty"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	Details      map[string]any         `json:"details,omitempty"`
	DurationMS   *int                   `json:"duration_ms,omitempty"`
}

// QueryFilter defines filters for querying audit logs.
type QueryFilter struct {
	ActorID  *uuid.UUID
	Category string
	Action   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

// QueryResult holds paginated audit log results.
type QueryResult struct {
	Entries []Entry `json:"audit_logs"`
	Total   int     `json:"total"`
	Limit   int     `json:"limit"`
	Offset  int     `json:"offset"`
}
