package teleport

import (
	"context"
	"fmt"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

// Client wraps the Teleport Go SDK client for a single cluster.
type Client struct {
	tc        *client.Client
	proxyAddr string
}

// NewClient creates a Teleport API client connected to the given proxy address.
//
// Supported credential providers:
//   - Identity file bytes (client.IdentityFileCredentials)
//   - Other credential types supported by the Teleport SDK
func NewClient(ctx context.Context, proxyAddr string, creds client.Credentials) (*Client, error) {
	tc, err := client.New(ctx, client.Config{
		Addrs:       []string{proxyAddr},
		Credentials: []client.Credentials{creds},
		DialOpts:    []grpc.DialOption{grpc.WithReturnConnectionError()},
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to teleport proxy %s: %w", proxyAddr, err)
	}

	return &Client{tc: tc, proxyAddr: proxyAddr}, nil
}

// Close disconnects from the Teleport proxy.
func (c *Client) Close() error {
	return c.tc.Close()
}

// Ping checks connectivity with the Teleport cluster.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.tc.Ping(ctx)
	if err != nil {
		return fmt.Errorf("pinging teleport cluster: %w", err)
	}
	return nil
}

// ListNodes returns all SSH nodes visible to the authenticated user.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	resources, err := client.GetAllResources[types.Server](ctx, c.tc, &proto.ListResourcesRequest{
		ResourceType: types.KindNode,
		Limit:        500,
	})
	if err != nil {
		return nil, fmt.Errorf("listing teleport nodes: %w", err)
	}

	nodes := make([]Node, 0, len(resources))
	for _, srv := range resources {
		labels := make(map[string]string)
		for k, v := range srv.GetAllLabels() {
			labels[k] = v
		}

		nodes = append(nodes, Node{
			ID:       srv.GetName(),
			Hostname: srv.GetHostname(),
			Addr:     srv.GetAddr(),
			Labels:   labels,
			OSType:   labels["os"],
		})
	}

	log.Debug().Int("count", len(nodes)).Str("proxy", c.proxyAddr).Msg("listed teleport nodes")
	return nodes, nil
}

// GenerateUserCerts requests short-lived SSH and TLS certificates from the
// Teleport auth server for the authenticated identity.
//
// The identity used to create the Client determines whose certificates are
// generated. The username/TTL in the request provide additional parameters.
func (c *Client) GenerateUserCerts(ctx context.Context, username string, ttl time.Duration) (*CertResponse, error) {
	certs, err := c.tc.GenerateUserCerts(ctx, proto.UserCertsRequest{
		Username: username,
		Expires:  time.Now().Add(ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("generating user certs: %w", err)
	}

	return &CertResponse{
		SSHCert:   certs.SSH,
		TLSCert:   certs.TLS,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}
