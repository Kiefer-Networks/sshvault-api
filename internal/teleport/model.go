package teleport

import (
	"time"

	"github.com/google/uuid"
)

// Cluster represents a registered Teleport cluster.
type Cluster struct {
	ID         uuid.UUID         `json:"id"`
	UserID     uuid.UUID         `json:"user_id"`
	Name       string            `json:"name"`
	ProxyAddr  string            `json:"proxy_addr"`
	AuthMethod string            `json:"auth_method"`
	Identity   []byte            `json:"-"`
	Metadata   map[string]any    `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Session holds a cached Teleport session for certificate issuance.
type Session struct {
	ID           uuid.UUID `json:"id"`
	ClusterID    uuid.UUID `json:"cluster_id"`
	UserID       uuid.UUID `json:"user_id"`
	SessionToken []byte    `json:"-"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// Node represents a server node discovered from a Teleport cluster.
type Node struct {
	ID       string            `json:"id"`
	Hostname string            `json:"hostname"`
	Addr     string            `json:"addr"`
	Labels   map[string]string `json:"labels,omitempty"`
	OSType   string            `json:"os_type,omitempty"`
}

// --- Request / Response DTOs ---

// RegisterClusterRequest is the body for POST /v1/teleport/clusters.
type RegisterClusterRequest struct {
	Name       string `json:"name"`
	ProxyAddr  string `json:"proxy_addr"`
	AuthMethod string `json:"auth_method"` // local, sso_oidc, sso_saml, identity_file
	Identity   []byte `json:"identity,omitempty"`
}

// LoginRequest is the body for POST /v1/teleport/clusters/{id}/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	OTPToken string `json:"otp_token,omitempty"`
}

// CertRequest is the body for POST /v1/teleport/clusters/{id}/certs.
type CertRequest struct {
	Username string `json:"username,omitempty"`
	TTL      string `json:"ttl,omitempty"` // e.g. "12h"
}

// CertResponse is returned by the certs endpoint.
type CertResponse struct {
	SSHCert    []byte    `json:"ssh_cert"`
	TLSCert    []byte    `json:"tls_cert"`
	PrivateKey []byte    `json:"private_key"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// SSOBeginResponse is returned when starting an SSO flow.
type SSOBeginResponse struct {
	RedirectURL string `json:"redirect_url"`
	RequestID   string `json:"request_id"`
}

// SSOStatusResponse is returned by the SSO status polling endpoint.
type SSOStatusResponse struct {
	Complete bool          `json:"complete"`
	Certs    *CertResponse `json:"certs,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// ClusterListResponse wraps a list of clusters.
type ClusterListResponse struct {
	Clusters []Cluster `json:"clusters"`
}

// NodeListResponse wraps a list of nodes.
type NodeListResponse struct {
	Nodes []Node `json:"nodes"`
}
