package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/netutil"
)

// DynamicClientRequest is the RFC 7591 / OIDC DCR JSON body (subset).
type DynamicClientRequest struct {
	RedirectURIs                      []string `json:"redirect_uris"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method"`
	GrantTypes                        []string `json:"grant_types"`
	ResponseTypes                     []string `json:"response_types"`
	ClientName                        string   `json:"client_name"`
	ClientURI                         string   `json:"client_uri"`
	LogoURI                           string   `json:"logo_uri"`
	Scope                             string   `json:"scope"` // space-delimited
	Contacts                          []string `json:"contacts"`
	TosURI                            string   `json:"tos_uri"`
	PolicyURI                         string   `json:"policy_uri"`
	JWKSURI                           string   `json:"jwks_uri"`
	SubjectType                       string   `json:"subject_type"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg"`
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI             string   `json:"frontchannel_logout_uri"`
	FrontChannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required"`
	BackChannelLogoutURI              string   `json:"backchannel_logout_uri"`
	BackChannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required"`
	RequirePKCE                       *bool    `json:"require_pkce"`
}

// DynamicClientResponse is returned by DCR create/read/update.
type DynamicClientResponse struct {
	ClientID                          string   `json:"client_id"`
	ClientSecret                      string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt                  int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt             int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken           string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI             string   `json:"registration_client_uri,omitempty"`
	RedirectURIs                      []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	ClientName                        string   `json:"client_name,omitempty"`
	ClientURI                         string   `json:"client_uri,omitempty"`
	LogoURI                           string   `json:"logo_uri,omitempty"`
	Scope                             string   `json:"scope,omitempty"`
	Contacts                          []string `json:"contacts,omitempty"`
	TosURI                            string   `json:"tos_uri,omitempty"`
	PolicyURI                         string   `json:"policy_uri,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	SubjectType                       string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg,omitempty"`
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris,omitempty"`
	FrontChannelLogoutURI             string   `json:"frontchannel_logout_uri,omitempty"`
	FrontChannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackChannelLogoutURI              string   `json:"backchannel_logout_uri,omitempty"`
	BackChannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required,omitempty"`
}

// RegisterDynamicClient creates a client via public DCR (RFC 7591).
func (f *Flow) RegisterDynamicClient(ctx context.Context, in DynamicClientRequest) (*DynamicClientResponse, error) {
	if !f.dcrEnabled() {
		return nil, fmt.Errorf("%w: dynamic client registration is disabled", ErrInvalidRequest)
	}
	client, err := f.buildDynamicClient(in)
	if err != nil {
		return nil, err
	}
	client.ID = uuid.New()
	client.TenantID = f.tenantID()
	client.ClientID = uuid.NewString()
	client.IsDynamic = true
	client.CreatedAt = time.Now().UTC()
	client.UpdatedAt = client.CreatedAt

	var rawSecret string
	if client.ClientType != domain.ClientTypePublic {
		rawSecret, client.ClientSecretHash, err = newRandomSecret()
		if err != nil {
			return nil, err
		}
	}

	rawRAT, hash, err := newRandomSecret()
	if err != nil {
		return nil, err
	}
	client.RegistrationAccessTokenHash = hash

	if err := f.clients.Create(ctx, client); err != nil {
		return nil, err
	}
	f.auditSuccess(ctx, domain.AuditEventClientCreated, domain.AuditActorSystem, client.ClientID, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectClient
		e.SubjectID = client.ClientID
		e.ClientID = client.ClientID
		e.Metadata = map[string]any{"source": "dcr"}
	})
	return f.dynamicClientResponse(client, rawSecret, rawRAT), nil
}

// GetDynamicClient returns a dynamically registered client (Bearer RAT).
func (f *Flow) GetDynamicClient(ctx context.Context, clientID, registrationAccessToken string) (*DynamicClientResponse, error) {
	client, err := f.authorizeDynamicClient(ctx, clientID, registrationAccessToken)
	if err != nil {
		return nil, err
	}
	return f.dynamicClientResponse(client, "", ""), nil
}

// UpdateDynamicClient replaces metadata of a dynamic client and rotates the RAT.
func (f *Flow) UpdateDynamicClient(ctx context.Context, clientID, registrationAccessToken string, in DynamicClientRequest) (*DynamicClientResponse, error) {
	existing, err := f.authorizeDynamicClient(ctx, clientID, registrationAccessToken)
	if err != nil {
		return nil, err
	}
	next, err := f.buildDynamicClient(in)
	if err != nil {
		return nil, err
	}
	next.ID = existing.ID
	next.TenantID = existing.TenantID
	next.ClientID = existing.ClientID
	next.ClientSecretHash = existing.ClientSecretHash
	next.IsDynamic = true
	next.CreatedAt = existing.CreatedAt
	next.UpdatedAt = time.Now().UTC()
	// Keep public/confidential unless auth method implies public.
	if next.ClientType == "" {
		next.ClientType = existing.ClientType
	}

	rawRAT, hash, err := newRandomSecret()
	if err != nil {
		return nil, err
	}
	next.RegistrationAccessTokenHash = hash

	if err := f.clients.Update(ctx, next); err != nil {
		return nil, err
	}
	f.auditSuccess(ctx, domain.AuditEventClientUpdated, domain.AuditActorSystem, next.ClientID, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectClient
		e.SubjectID = next.ClientID
		e.ClientID = next.ClientID
		e.Metadata = map[string]any{"source": "dcr"}
	})
	return f.dynamicClientResponse(next, "", rawRAT), nil
}

// DeleteDynamicClient soft-deletes a dynamically registered client.
func (f *Flow) DeleteDynamicClient(ctx context.Context, clientID, registrationAccessToken string) error {
	client, err := f.authorizeDynamicClient(ctx, clientID, registrationAccessToken)
	if err != nil {
		return err
	}
	if err := f.clients.Delete(ctx, client.TenantID, client.ID); err != nil {
		return err
	}
	f.auditSuccess(ctx, domain.AuditEventClientDeleted, domain.AuditActorSystem, client.ClientID, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectClient
		e.SubjectID = client.ClientID
		e.ClientID = client.ClientID
		e.Metadata = map[string]any{"source": "dcr"}
	})
	return nil
}

func (f *Flow) dcrEnabled() bool {
	return f.cfg != nil && f.cfg.OIDC.DynamicClientRegistration.Enabled
}

func (f *Flow) authorizeDynamicClient(ctx context.Context, clientID, rawRAT string) (*domain.Client, error) {
	if !f.dcrEnabled() {
		return nil, fmt.Errorf("%w: dynamic client registration is disabled", ErrInvalidRequest)
	}
	clientID = strings.TrimSpace(clientID)
	rawRAT = strings.TrimSpace(rawRAT)
	if clientID == "" || rawRAT == "" {
		return nil, ErrInvalidToken
	}
	client, err := f.clients.GetByClientID(ctx, f.tenantID(), clientID)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(clientSecretDummyHash(), []byte(rawRAT))
		return nil, ErrInvalidToken
	}
	if !client.IsDynamic || client.RegistrationAccessTokenHash == "" {
		_ = bcrypt.CompareHashAndPassword(clientSecretDummyHash(), []byte(rawRAT))
		return nil, ErrInvalidToken
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.RegistrationAccessTokenHash), []byte(rawRAT)); err != nil {
		return nil, ErrInvalidToken
	}
	return client, nil
}

func (f *Flow) buildDynamicClient(in DynamicClientRequest) (*domain.Client, error) {
	if len(in.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: redirect_uris is required", ErrInvalidRequest)
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("%w: redirect_uris: %v", ErrInvalidRequest, err)
		}
	}
	for _, u := range in.PostLogoutRedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("%w: post_logout_redirect_uris: %v", ErrInvalidRequest, err)
		}
	}
	if u := strings.TrimSpace(in.FrontChannelLogoutURI); u != "" {
		if err := netutil.ValidateOutboundURL(u); err != nil {
			return nil, fmt.Errorf("%w: frontchannel_logout_uri: %v", ErrInvalidRequest, err)
		}
	}
	if u := strings.TrimSpace(in.BackChannelLogoutURI); u != "" {
		if err := netutil.ValidateOutboundURL(u); err != nil {
			return nil, fmt.Errorf("%w: backchannel_logout_uri: %v", ErrInvalidRequest, err)
		}
	}
	if u := strings.TrimSpace(in.JWKSURI); u != "" {
		if err := netutil.ValidateOutboundURL(u); err != nil {
			return nil, fmt.Errorf("%w: jwks_uri: %v", ErrInvalidRequest, err)
		}
	}

	authMethod := strings.TrimSpace(in.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = string(domain.TokenEndpointAuthClientSecretBasic)
	}
	clientType := domain.ClientTypeConfidential
	if authMethod == string(domain.TokenEndpointAuthNone) {
		clientType = domain.ClientTypePublic
	}

	grantTypes := domain.GrantTypesFromStrings(in.GrantTypes)
	if len(grantTypes) == 0 {
		grantTypes = []domain.GrantType{domain.GrantTypeAuthorizationCode}
	}
	for _, g := range grantTypes {
		switch g {
		case domain.GrantTypeAuthorizationCode, domain.GrantTypeRefreshToken, domain.GrantTypeClientCredentials:
		default:
			return nil, fmt.Errorf("%w: unsupported grant_type %q", ErrInvalidRequest, g)
		}
	}

	responseTypes := in.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, rt := range responseTypes {
		if rt != "code" {
			return nil, fmt.Errorf("%w: unsupported response_type %q", ErrInvalidRequest, rt)
		}
	}

	scopes := splitScope(in.Scope)
	if len(scopes) == 0 {
		scopes = append([]string(nil), f.cfg.OIDC.DynamicClientRegistration.DefaultScopes...)
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	subjectType := domain.SubjectTypePublic
	if raw := strings.TrimSpace(in.SubjectType); raw != "" {
		subjectType = domain.SubjectType(raw)
		if subjectType != domain.SubjectTypePublic && subjectType != domain.SubjectTypePairwise {
			return nil, fmt.Errorf("%w: invalid subject_type", ErrInvalidRequest)
		}
	}

	requirePKCE := clientType == domain.ClientTypePublic
	if in.RequirePKCE != nil {
		requirePKCE = *in.RequirePKCE
	}

	idTokenAlg := strings.TrimSpace(in.IDTokenSignedResponseAlg)
	if idTokenAlg == "" {
		idTokenAlg = "RS256"
	}

	c := &domain.Client{
		Name:                              strings.TrimSpace(in.ClientName),
		ClientType:                        clientType,
		GrantTypes:                        grantTypes,
		ResponseTypes:                     responseTypes,
		RedirectURIs:                      append([]string(nil), in.RedirectURIs...),
		AllowedScopes:                     scopes,
		DefaultScopes:                     scopes,
		TokenEndpointAuthMethod:           domain.TokenEndpointAuthMethod(authMethod),
		RequirePKCE:                       requirePKCE,
		SubjectType:                       subjectType,
		IDTokenSignedAlg:                  idTokenAlg,
		UserinfoSignedAlg:                 "none",
		PostLogoutURIs:                    append([]string(nil), in.PostLogoutRedirectURIs...),
		FrontChannelLogoutURI:             strings.TrimSpace(in.FrontChannelLogoutURI),
		FrontChannelLogoutSessionRequired: in.FrontChannelLogoutSessionRequired,
		BackChannelLogoutURI:              strings.TrimSpace(in.BackChannelLogoutURI),
		BackChannelLogoutSessionRequired:  in.BackChannelLogoutSessionRequired,
		LogoURI:                           strings.TrimSpace(in.LogoURI),
		ClientURI:                         strings.TrimSpace(in.ClientURI),
		PolicyURI:                         strings.TrimSpace(in.PolicyURI),
		TosURI:                            strings.TrimSpace(in.TosURI),
		Contacts:                          append([]string(nil), in.Contacts...),
		JWKSURI:                           strings.TrimSpace(in.JWKSURI),
		Protocols:                         []string{"oauth2", "oidc"},
	}
	if c.Name == "" {
		c.Name = "dynamic-client"
	}
	return c, nil
}

func (f *Flow) dynamicClientResponse(c *domain.Client, rawSecret, rawRAT string) *DynamicClientResponse {
	scopes := c.AllowedScopes
	if scopes == nil {
		scopes = c.DefaultScopes
	}
	out := &DynamicClientResponse{
		ClientID:                          c.ClientID,
		ClientSecret:                      rawSecret,
		ClientIDIssuedAt:                  c.CreatedAt.Unix(),
		ClientSecretExpiresAt:             0,
		RegistrationAccessToken:           rawRAT,
		RegistrationClientURI:             strings.TrimRight(f.issuer(), "/") + "/oauth2/register/" + url.PathEscape(c.ClientID),
		RedirectURIs:                      c.RedirectURIs,
		TokenEndpointAuthMethod:           string(c.TokenEndpointAuthMethod),
		GrantTypes:                        domain.GrantTypesToStrings(c.GrantTypes),
		ResponseTypes:                     c.ResponseTypes,
		ClientName:                        c.Name,
		ClientURI:                         c.ClientURI,
		LogoURI:                           c.LogoURI,
		Scope:                             strings.Join(scopes, " "),
		Contacts:                          c.Contacts,
		TosURI:                            c.TosURI,
		PolicyURI:                         c.PolicyURI,
		JWKSURI:                           c.JWKSURI,
		SubjectType:                       string(c.SubjectType),
		IDTokenSignedResponseAlg:          c.IDTokenSignedAlg,
		PostLogoutRedirectURIs:            c.PostLogoutURIs,
		FrontChannelLogoutURI:             c.FrontChannelLogoutURI,
		FrontChannelLogoutSessionRequired: c.FrontChannelLogoutSessionRequired,
		BackChannelLogoutURI:              c.BackChannelLogoutURI,
		BackChannelLogoutSessionRequired:  c.BackChannelLogoutSessionRequired,
	}
	if rawSecret == "" && c.ClientType != domain.ClientTypePublic {
		// Read path: never re-emit secret.
		out.ClientSecret = ""
	}
	return out
}

func splitScope(raw string) []string {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func validateRedirectURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Fragment != "" {
		return fmt.Errorf("fragment not allowed")
	}
	if u.Host == "" || u.Scheme == "" {
		return fmt.Errorf("absolute uri required")
	}
	switch u.Scheme {
	case "https":
		if ip := net.ParseIP(u.Hostname()); ip != nil && netutil.IsBlockedIP(ip) {
			return fmt.Errorf("host address is not allowed")
		}
		return nil
	case "http":
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("http only allowed for localhost")
	default:
		return fmt.Errorf("scheme must be https (or http://localhost)")
	}
}

func newRandomSecret() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hash = string(hashBytes)
	return
}
