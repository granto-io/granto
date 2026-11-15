package adminclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
)

// Config configures the Admin gRPC connection.
type Config struct {
	// Addr is a host:port dial target.
	Addr string
	// Token is the Admin bearer token.
	Token string
	// TLSCAFile optionally pins a private CA.
	TLSCAFile string
}

type grpcClient struct {
	conn *grpc.ClientConn
	rpc  adminv1.OAuth2ServiceClient
}

// New builds a client. Plain text is allowed only for loopback addresses;
// everything else requires TLS.
func New(cfg Config) (Client, error) {
	cfg.Addr = strings.TrimSpace(cfg.Addr)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Addr == "" {
		return nil, fmt.Errorf("adminclient: addr is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("adminclient: token is required")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("adminclient: addr %q must be host:port: %w", cfg.Addr, err)
	}

	creds, err := transportCredentials(host, cfg.TLSCAFile)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(
		cfg.Addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithChainUnaryInterceptor(bearerInterceptor(cfg.Token)),
	)
	if err != nil {
		return nil, fmt.Errorf("adminclient: dial %s: %w", cfg.Addr, err)
	}
	return &grpcClient{conn: conn, rpc: adminv1.NewOAuth2ServiceClient(conn)}, nil
}

func (c *grpcClient) Close() error {
	return c.conn.Close()
}

// transportCredentials enforces TLS outside loopback.
func transportCredentials(host, caFile string) (credentials.TransportCredentials, error) {
	if isLoopbackHost(host) {
		return insecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if host != "" {
		if net.ParseIP(host) == nil {
			tlsCfg.ServerName = host
		}
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("adminclient: read tls ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("adminclient: tls ca %s contains no certificates", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func bearerInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (c *grpcClient) GetLogin(ctx context.Context, challengeID string) (*LoginRequest, error) {
	resp, err := c.rpc.GetLoginRequest(ctx, &adminv1.GetLoginRequestRequest{LoginChallenge: challengeID})
	if err != nil {
		return nil, fmt.Errorf("adminclient: get login request: %w", err)
	}
	return &LoginRequest{
		ChallengeID:       resp.GetChallenge(),
		ClientID:          resp.GetClientId(),
		RequestURL:        resp.GetRequestUrl(),
		RedirectURI:       resp.GetRedirectUri(),
		RequestedScope:    resp.GetRequestedScope(),
		RequestedAudience: resp.GetRequestedAccessTokenAudience(),
		Skip:              resp.GetSkip(),
		Subject:           resp.GetSubject(),
		SessionID:         resp.GetSessionId(),
		LoginHint:         oidcLoginHint(resp.GetOidcContext()),
		AcceptToken:       resp.GetAcceptToken(),
	}, nil
}

func (c *grpcClient) AcceptLogin(ctx context.Context, in AcceptLoginInput) (string, error) {
	ctxStruct, err := mapToStruct(in.Context)
	if err != nil {
		return "", fmt.Errorf("adminclient: accept login: %w", err)
	}
	resp, err := c.rpc.AcceptLoginRequest(ctx, &adminv1.AcceptLoginRequestRequest{
		LoginChallenge: in.ChallengeID,
		Body: &adminv1.AcceptLoginBody{
			Subject:                   in.Subject,
			Remember:                  in.Remember,
			RememberFor:               in.RememberFor,
			Acr:                       in.ACR,
			Amr:                       in.AMR,
			Context:                   ctxStruct,
			IdentityProviderSessionId: in.IdentityProviderSessionID,
			AcceptToken:               in.AcceptToken,
		},
	})
	if err != nil {
		return "", fmt.Errorf("adminclient: accept login: %w", err)
	}
	return resp.GetRedirectTo(), nil
}

func (c *grpcClient) RejectLogin(ctx context.Context, in RejectInput) (string, error) {
	resp, err := c.rpc.RejectLoginRequest(ctx, &adminv1.RejectLoginRequestRequest{
		LoginChallenge: in.ChallengeID,
		Body: &adminv1.RejectOAuth2Body{
			Error:            in.Error,
			ErrorDescription: in.ErrorDescription,
			ErrorHint:        in.ErrorHint,
			AcceptToken:      in.AcceptToken,
		},
	})
	if err != nil {
		return "", fmt.Errorf("adminclient: reject login: %w", err)
	}
	return resp.GetRedirectTo(), nil
}

func (c *grpcClient) GetConsent(ctx context.Context, challengeID string) (*ConsentRequest, error) {
	resp, err := c.rpc.GetConsentRequest(ctx, &adminv1.GetConsentRequestRequest{ConsentChallenge: challengeID})
	if err != nil {
		return nil, fmt.Errorf("adminclient: get consent request: %w", err)
	}
	return &ConsentRequest{
		ChallengeID:       resp.GetChallenge(),
		ClientID:          resp.GetClientId(),
		RequestURL:        resp.GetRequestUrl(),
		RedirectURI:       resp.GetRedirectUri(),
		RequestedScope:    resp.GetRequestedScope(),
		RequestedAudience: resp.GetRequestedAccessTokenAudience(),
		Skip:              resp.GetSkip(),
		Subject:           resp.GetSubject(),
		SessionID:         resp.GetSessionId(),
		LoginChallengeID:  resp.GetLoginChallenge(),
		ACR:               resp.GetAcr(),
		AMR:               resp.GetAmr(),
		LoginHint:         oidcLoginHint(resp.GetOidcContext()),
		AcceptToken:       resp.GetAcceptToken(),
	}, nil
}

func (c *grpcClient) AcceptConsent(ctx context.Context, in AcceptConsentInput) (string, error) {
	resp, err := c.rpc.AcceptConsentRequest(ctx, &adminv1.AcceptConsentRequestRequest{
		ConsentChallenge: in.ChallengeID,
		Body: &adminv1.AcceptConsentBody{
			GrantScope:    in.GrantScope,
			GrantScopeSet: in.GrantScopeSet,
			Remember:      in.Remember,
			RememberFor:   in.RememberFor,
			AcceptToken:   in.AcceptToken,
		},
	})
	if err != nil {
		return "", fmt.Errorf("adminclient: accept consent: %w", err)
	}
	return resp.GetRedirectTo(), nil
}

func (c *grpcClient) RejectConsent(ctx context.Context, in RejectInput) (string, error) {
	resp, err := c.rpc.RejectConsentRequest(ctx, &adminv1.RejectConsentRequestRequest{
		ConsentChallenge: in.ChallengeID,
		Body: &adminv1.RejectOAuth2Body{
			Error:            in.Error,
			ErrorDescription: in.ErrorDescription,
			ErrorHint:        in.ErrorHint,
			AcceptToken:      in.AcceptToken,
		},
	})
	if err != nil {
		return "", fmt.Errorf("adminclient: reject consent: %w", err)
	}
	return resp.GetRedirectTo(), nil
}

func mapToStruct(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil, fmt.Errorf("adminclient: encode context: %w", err)
	}
	return s, nil
}

// oidcLoginHint extracts login_hint from an OIDC context that may be absent.
func oidcLoginHint(oc *adminv1.OIDCContext) string {
	if oc == nil {
		return ""
	}
	return oc.GetLoginHint()
}
