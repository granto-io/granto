package public_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/oidc"
	"github.com/granto-io/granto/core/internal/repository"
	"github.com/granto-io/granto/core/internal/transport/public"
)

func TestRegisterHTTPCreateAndManage(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example", AccessTokenTTL: time.Hour},
		OIDC: config.OIDCConfig{
			DynamicClientRegistration: config.DynamicClientRegistrationConfig{
				Enabled:       true,
				DefaultScopes: []string{"openid"},
			},
		},
		Session: config.SessionConfig{DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	clients := &dcrMemClients{byID: map[string]*domain.Client{}}
	flow := oauth2.NewFlow(cfg, clients, nil, nil, nil, nil, nil, nil, nil, nil)
	h := public.NewHandler(nil, cfg, flow, nil, oidc.NewDiscovery(cfg))
	mux := public.NewRouter(h, public.Options{})

	body := `{"redirect_uris":["https://app.example/cb"],"client_name":"http-demo"}`
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	clientID, _ := created["client_id"].(string)
	rat, _ := created["registration_access_token"].(string)
	if clientID == "" || rat == "" {
		t.Fatalf("created=%#v", created)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth2/register/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+rat)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr2.Code, rr2.Body.String())
	}

	upd := `{"redirect_uris":["https://app.example/cb"],"client_name":"renamed"}`
	req3 := httptest.NewRequest(http.MethodPut, "/oauth2/register/"+clientID, bytes.NewBufferString(upd))
	req3.Header.Set("Authorization", "Bearer "+rat)
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rr3.Code, rr3.Body.String())
	}
	var updated map[string]any
	_ = json.NewDecoder(rr3.Body).Decode(&updated)
	newRAT, _ := updated["registration_access_token"].(string)

	req4 := httptest.NewRequest(http.MethodDelete, "/oauth2/register/"+clientID, nil)
	req4.Header.Set("Authorization", "Bearer "+newRAT)
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusNoContent {
		t.Fatalf("DELETE status=%d body=%s", rr4.Code, rr4.Body.String())
	}
}

func TestRegisterHTTPDisabledIs404(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Token: config.TokenConfig{Issuer: "https://auth.example"}}
	h := public.NewHandler(nil, cfg, nil, nil, oidc.NewDiscovery(cfg))
	rr := httptest.NewRecorder()
	public.NewRouter(h, public.Options{}).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/oauth2/register", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rr.Code)
	}
}

type dcrMemClients struct {
	byID map[string]*domain.Client
}

func (m *dcrMemClients) GetByClientID(_ context.Context, _ uuid.UUID, clientID string) (*domain.Client, error) {
	c, ok := m.byID[clientID]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	cp := *c
	return &cp, nil
}
func (m *dcrMemClients) GetByID(_ context.Context, tenantID, id uuid.UUID) (*domain.Client, error) {
	for _, c := range m.byID {
		if c.ID == id && c.TenantID == tenantID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, domain.ErrClientNotFound
}
func (m *dcrMemClients) List(context.Context, uuid.UUID, repository.ClientFilter) ([]*domain.Client, error) {
	return nil, nil
}
func (m *dcrMemClients) Create(_ context.Context, c *domain.Client) error {
	cp := *c
	m.byID[c.ClientID] = &cp
	return nil
}
func (m *dcrMemClients) Update(_ context.Context, c *domain.Client) error {
	if _, ok := m.byID[c.ClientID]; !ok {
		return domain.ErrClientNotFound
	}
	cp := *c
	m.byID[c.ClientID] = &cp
	return nil
}
func (m *dcrMemClients) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	for cid, c := range m.byID {
		if c.ID == id && c.TenantID == tenantID {
			delete(m.byID, cid)
			return nil
		}
	}
	return domain.ErrClientNotFound
}
