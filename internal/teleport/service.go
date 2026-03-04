package teleport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/teleport/api/client"
	"github.com/rs/zerolog/log"
)

// validAuthMethods defines the accepted authentication methods.
var validAuthMethods = map[string]bool{
	"local":         true,
	"sso_oidc":      true,
	"sso_saml":      true,
	"identity_file": true,
}

const defaultCertTTL = 12 * time.Hour

// Service implements business logic for Teleport cluster management.
type Service struct {
	repo Repository
}

// NewService creates a new Teleport service.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// RegisterCluster registers a new Teleport cluster for the user.
func (s *Service) RegisterCluster(ctx context.Context, userID uuid.UUID, req RegisterClusterRequest) (*Cluster, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("cluster name is required")
	}
	if len(req.Name) > 255 {
		return nil, fmt.Errorf("cluster name too long")
	}
	if req.ProxyAddr == "" {
		return nil, fmt.Errorf("proxy address is required")
	}
	if len(req.ProxyAddr) > 512 {
		return nil, fmt.Errorf("proxy address too long")
	}
	if err := validateProxyAddr(req.ProxyAddr); err != nil {
		return nil, err
	}
	if req.AuthMethod == "" {
		req.AuthMethod = "local"
	}
	if !validAuthMethods[req.AuthMethod] {
		return nil, fmt.Errorf("invalid auth method")
	}
	if len(req.Identity) > 1<<20 { // 1 MB limit
		return nil, fmt.Errorf("identity file too large")
	}

	c := &Cluster{
		UserID:     userID,
		Name:       req.Name,
		ProxyAddr:  req.ProxyAddr,
		AuthMethod: req.AuthMethod,
		Identity:   req.Identity,
		Metadata:   make(map[string]any),
	}

	if err := s.repo.CreateCluster(ctx, c); err != nil {
		return nil, err
	}

	log.Info().Str("cluster_id", c.ID.String()).Str("proxy", c.ProxyAddr).Msg("teleport cluster registered")
	return c, nil
}

// ListClusters returns all clusters for the user.
func (s *Service) ListClusters(ctx context.Context, userID uuid.UUID) ([]Cluster, error) {
	return s.repo.ListClusters(ctx, userID)
}

// GetCluster returns a single cluster.
func (s *Service) GetCluster(ctx context.Context, clusterID, userID uuid.UUID) (*Cluster, error) {
	return s.repo.GetCluster(ctx, clusterID, userID)
}

// DeleteCluster removes a cluster and cascading sessions.
func (s *Service) DeleteCluster(ctx context.Context, clusterID, userID uuid.UUID) error {
	return s.repo.DeleteCluster(ctx, clusterID, userID)
}

// Login authenticates to a Teleport cluster using local credentials and
// stores the session for later certificate generation.
func (s *Service) Login(ctx context.Context, userID, clusterID uuid.UUID, req LoginRequest) error {
	cluster, err := s.repo.GetCluster(ctx, clusterID, userID)
	if err != nil {
		return err
	}
	if cluster == nil {
		return fmt.Errorf("cluster not found")
	}

	// Build credentials based on auth method.
	creds, err := s.clusterCredentials(cluster)
	if err != nil {
		return err
	}

	tc, err := NewClient(ctx, cluster.ProxyAddr, creds)
	if err != nil {
		return fmt.Errorf("connecting to cluster: %w", err)
	}
	defer tc.Close()

	// Verify connectivity.
	if err := tc.Ping(ctx); err != nil {
		return err
	}

	log.Info().Str("cluster_id", clusterID.String()).Msg("teleport login successful")
	return nil
}

// ListNodes returns all SSH nodes from a Teleport cluster.
func (s *Service) ListNodes(ctx context.Context, userID, clusterID uuid.UUID) ([]Node, error) {
	cluster, err := s.repo.GetCluster(ctx, clusterID, userID)
	if err != nil {
		return nil, err
	}
	if cluster == nil {
		return nil, fmt.Errorf("cluster not found")
	}

	creds, err := s.clusterCredentials(cluster)
	if err != nil {
		return nil, err
	}

	tc, err := NewClient(ctx, cluster.ProxyAddr, creds)
	if err != nil {
		return nil, err
	}
	defer tc.Close()

	return tc.ListNodes(ctx)
}

// GenerateCerts issues short-lived SSH certificates for the user.
//
// The identity file stored for the cluster provides the key material.
// Teleport generates certificates for the authenticated identity.
func (s *Service) GenerateCerts(ctx context.Context, userID, clusterID uuid.UUID, req CertRequest) (*CertResponse, error) {
	cluster, err := s.repo.GetCluster(ctx, clusterID, userID)
	if err != nil {
		return nil, err
	}
	if cluster == nil {
		return nil, fmt.Errorf("cluster not found")
	}

	creds, err := s.clusterCredentials(cluster)
	if err != nil {
		return nil, err
	}

	tc, err := NewClient(ctx, cluster.ProxyAddr, creds)
	if err != nil {
		return nil, err
	}
	defer tc.Close()

	username := req.Username
	if username == "" {
		if u, ok := cluster.Metadata["username"].(string); ok && u != "" {
			username = u
		} else {
			return nil, fmt.Errorf("username is required")
		}
	}

	ttl := defaultCertTTL
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err == nil && parsed > 0 && parsed <= 24*time.Hour {
			ttl = parsed
		}
	}

	resp, err := tc.GenerateUserCerts(ctx, username, ttl)
	if err != nil {
		return nil, err
	}

	// The identity file's private key is needed by the Flutter client to sign
	// the SSH handshake. Include it in the response.
	resp.PrivateKey = cluster.Identity

	return resp, nil
}

// IsUnlocked checks whether the user has purchased the Teleport addon.
func (s *Service) IsUnlocked(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.repo.IsTeleportUnlocked(ctx, userID)
}

// SetUnlocked marks the user as having purchased the Teleport addon.
func (s *Service) SetUnlocked(ctx context.Context, userID uuid.UUID, unlocked bool) error {
	return s.repo.SetTeleportUnlocked(ctx, userID, unlocked)
}

// CleanupExpiredSessions deletes sessions that have passed their expiry.
func (s *Service) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredSessions(ctx)
}

// validateProxyAddr checks that the proxy address is a valid host:port and
// rejects private/loopback addresses to prevent SSRF.
func validateProxyAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Try adding default port if none specified.
		host = addr
		port = "443"
		if _, _, err2 := net.SplitHostPort(host + ":" + port); err2 != nil {
			return fmt.Errorf("invalid proxy address format (expected host:port)")
		}
	}
	if host == "" || port == "" {
		return fmt.Errorf("proxy address must include host and port")
	}

	// Reject loopback and private IP ranges.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("proxy address must not be a private or loopback address")
		}
	}

	// Reject localhost variants.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("proxy address must not be a local address")
	}

	return nil
}

// clusterCredentials resolves the appropriate Teleport credentials for a cluster.
func (s *Service) clusterCredentials(cluster *Cluster) (client.Credentials, error) {
	switch cluster.AuthMethod {
	case "identity_file":
		if len(cluster.Identity) == 0 {
			return nil, fmt.Errorf("no identity file for cluster %s", cluster.ID)
		}
		return client.LoadIdentityFileFromString(string(cluster.Identity)), nil
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", cluster.AuthMethod)
	}
}
