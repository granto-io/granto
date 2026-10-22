package oauth2_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestRegisterDynamicClientRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	d.cfg.OIDC.DynamicClientRegistration.Enabled = true
	d.cfg.OIDC.DynamicClientRegistration.DefaultScopes = []string{"openid", "profile"}

	created, err := d.flow.RegisterDynamicClient(ctx, oauth2.DynamicClientRequest{
		RedirectURIs: []string{"https://app.example/cb"},
		ClientName:   "demo",
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
	if created.ClientID == "" || created.ClientSecret == "" || created.RegistrationAccessToken == "" {
		t.Fatalf("missing credentials: %+v", created)
	}
	if !strings.Contains(created.RegistrationClientURI, "/oauth2/register/"+created.ClientID) {
		t.Fatalf("RegistrationClientURI = %q", created.RegistrationClientURI)
	}
	if created.Scope != "openid profile" {
		t.Fatalf("Scope = %q, want default scopes", created.Scope)
	}

	got, err := d.flow.GetDynamicClient(ctx, created.ClientID, created.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("GetDynamicClient: %v", err)
	}
	if got.ClientSecret != "" {
		t.Fatal("GET must not re-emit client_secret")
	}
	if got.ClientName != "demo" {
		t.Fatalf("ClientName = %q", got.ClientName)
	}

	updated, err := d.flow.UpdateDynamicClient(ctx, created.ClientID, created.RegistrationAccessToken, oauth2.DynamicClientRequest{
		RedirectURIs: []string{"https://app.example/cb2"},
		ClientName:   "demo-2",
		GrantTypes:   []string{"authorization_code"},
		Scope:        "openid",
	})
	if err != nil {
		t.Fatalf("UpdateDynamicClient: %v", err)
	}
	if updated.RegistrationAccessToken == "" || updated.RegistrationAccessToken == created.RegistrationAccessToken {
		t.Fatal("update must rotate registration_access_token")
	}
	if _, err := d.flow.GetDynamicClient(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, oauth2.ErrInvalidToken) {
		t.Fatalf("old RAT should fail: %v", err)
	}
	if _, err := d.flow.GetDynamicClient(ctx, created.ClientID, updated.RegistrationAccessToken); err != nil {
		t.Fatalf("new RAT: %v", err)
	}

	if err := d.flow.DeleteDynamicClient(ctx, created.ClientID, updated.RegistrationAccessToken); err != nil {
		t.Fatalf("DeleteDynamicClient: %v", err)
	}
	if _, err := d.clients.GetByClientID(ctx, domain.DefaultTenantID, created.ClientID); !errors.Is(err, domain.ErrClientNotFound) {
		t.Fatalf("client should be deleted: %v", err)
	}
}

func TestRegisterDynamicClientDisabled(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	_, err := d.flow.RegisterDynamicClient(t.Context(), oauth2.DynamicClientRequest{
		RedirectURIs: []string{"https://app.example/cb"},
	})
	if !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}

func TestRegisterDynamicClientRejectsPrivateRedirect(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	d.cfg.OIDC.DynamicClientRegistration.Enabled = true
	_, err := d.flow.RegisterDynamicClient(t.Context(), oauth2.DynamicClientRequest{
		RedirectURIs: []string{"https://10.0.0.1/cb"},
	})
	if !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}
