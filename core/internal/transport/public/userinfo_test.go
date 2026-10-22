package public

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/repository"
)

type uiMemTokens struct {
	at map[string]*domain.AccessToken
}

func (m *uiMemTokens) CreateAccessToken(_ context.Context, t *domain.AccessToken) error {
	if m.at == nil {
		m.at = map[string]*domain.AccessToken{}
	}
	cp := *t
	m.at[t.TokenHash] = &cp
	return nil
}
func (m *uiMemTokens) GetAccessToken(_ context.Context, _ uuid.UUID, hash string) (*domain.AccessToken, error) {
	t, ok := m.at[hash]
	if !ok {
		return nil, domain.ErrAccessTokenNotFound
	}
	cp := *t
	if cp.IsExpired() {
		return &cp, domain.ErrAccessTokenExpired
	}
	return &cp, nil
}
func (m *uiMemTokens) RevokeAccessToken(context.Context, uuid.UUID, string) error { return nil }
func (m *uiMemTokens) RevokeAccessTokenByJTI(context.Context, uuid.UUID, string) error {
	return nil
}
func (m *uiMemTokens) CreateRefreshToken(context.Context, *domain.RefreshToken) error {
	return nil
}
func (m *uiMemTokens) GetRefreshToken(context.Context, uuid.UUID, string) (*domain.RefreshToken, error) {
	return nil, domain.ErrRefreshTokenNotFound
}
func (m *uiMemTokens) RotateRefreshToken(context.Context, uuid.UUID, string, *domain.RefreshToken) error {
	return nil
}
func (m *uiMemTokens) RevokeRefreshToken(context.Context, uuid.UUID, string) error { return nil }
func (m *uiMemTokens) RevokeRefreshTokensBySession(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (m *uiMemTokens) ListClientIDsBySession(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	return nil, nil
}

type uiStubClients struct{}

func (uiStubClients) GetByClientID(context.Context, uuid.UUID, string) (*domain.Client, error) {
	return nil, domain.ErrClientNotFound
}
func (uiStubClients) GetByID(context.Context, uuid.UUID, uuid.UUID) (*domain.Client, error) {
	return nil, domain.ErrClientNotFound
}
func (uiStubClients) List(context.Context, uuid.UUID, repository.ClientFilter) ([]*domain.Client, error) {
	return nil, nil
}
func (uiStubClients) Create(context.Context, *domain.Client) error { return nil }
func (uiStubClients) Update(context.Context, *domain.Client) error { return nil }
func (uiStubClients) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func TestHandleUserinfo(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	tokens := &uiMemTokens{}
	cfg := &config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example"},
	}
	flow := oauth2.NewFlow(cfg, uiStubClients{}, nil, nil, nil, nil, nil, tokens, nil, nil, nil)
	h := NewHandler(slog.Default(), cfg, flow, nil, nil)

	raw := "ui-bearer-token"
	if err := tokens.CreateAccessToken(ctx, &domain.AccessToken{
		TokenHash: domain.HashToken(raw),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		Scopes:    []string{"openid"},
		Extra: map[string]any{
			"id_token": map[string]any{"email": "a@b.c"},
		},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	t.Run("bearer success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		rec := httptest.NewRecorder()
		h.handleUserinfo(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("json: %v", err)
		}
		if body["sub"] != "user-1" || body["email"] != "a@b.c" {
			t.Fatalf("body = %#v", body)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		rec := httptest.NewRecorder()
		h.handleUserinfo(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_request") &&
			!strings.Contains(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("post form access_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/userinfo", strings.NewReader("access_token="+raw))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.handleUserinfo(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}
