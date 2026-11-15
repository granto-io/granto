// Package identityclient is the consent service's typed client for the
// identity service's public gRPC contract (IdentityService).
//
// It implements pluginapi.IdentityClient so plugins stay decoupled from the
// transport. The engine wires it from the configured identity service
// address.
package identityclient

import (
	"context"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	identityv1 "github.com/granto-io/granto/identity/gen/identity/v1"
)

// Config configures the identity gRPC connection.
type Config struct {
	// Addr is a host:port dial target.
	Addr string
}

// Client calls the identity IdentityService.
type Client struct {
	conn *grpc.ClientConn
	rpc  identityv1.IdentityServiceClient
}

// New builds a client.
//
// Transport is always plain text. Identity is a host-internal service (not
// meant to be reachable outside the deployment's own network, see D-048);
// that boundary is enforced by not publishing/routing its port beyond that
// network, not by requiring the dial address to be the loopback interface.
// A literal loopback address still works (single-process / same-container
// deployments); a container-network hostname (e.g. Docker Compose service
// DNS) works too, as long as the operator does not expose the port further.
// TLS is a later step for when identity crosses a real network boundary.
func New(cfg Config) (*Client, error) {
	cfg.Addr = strings.TrimSpace(cfg.Addr)
	if cfg.Addr == "" {
		return nil, fmt.Errorf("identityclient: addr is required")
	}
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return nil, fmt.Errorf("identityclient: addr %q must be host:port: %w", cfg.Addr, err)
	}

	conn, err := grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("identityclient: dial %s: %w", cfg.Addr, err)
	}
	return &Client{conn: conn, rpc: identityv1.NewIdentityServiceClient(conn)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// GetOrCreateUserByEmail implements pluginapi.IdentityClient.
func (c *Client) GetOrCreateUserByEmail(ctx context.Context, email string) (string, string, error) {
	resp, err := c.rpc.GetOrCreateUserByEmail(ctx, &identityv1.GetOrCreateUserByEmailRequest{Email: email})
	if err != nil {
		return "", "", fmt.Errorf("identityclient: get or create user: %w", err)
	}
	return resp.GetId(), resp.GetEmail(), nil
}
