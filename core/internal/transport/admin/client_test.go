package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
)

type mockClients struct {
	createFn func(ctx context.Context, c *domain.Client) error
	getByID  func(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	listFn   func(ctx context.Context, tenantID uuid.UUID, filter repository.ClientFilter) ([]*domain.Client, error)
	updateFn func(ctx context.Context, c *domain.Client) error
	deleteFn func(ctx context.Context, id uuid.UUID) error

	lastCreate *domain.Client
	lastFilter repository.ClientFilter
	lastTenant uuid.UUID
}

func (m *mockClients) GetByClientID(context.Context, uuid.UUID, string) (*domain.Client, error) {
	return nil, errors.New("not implemented")
}
func (m *mockClients) GetByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	return m.getByID(ctx, id)
}
func (m *mockClients) List(ctx context.Context, tenantID uuid.UUID, filter repository.ClientFilter) ([]*domain.Client, error) {
	m.lastTenant = tenantID
	m.lastFilter = filter
	return m.listFn(ctx, tenantID, filter)
}
func (m *mockClients) Create(ctx context.Context, client *domain.Client) error {
	m.lastCreate = client
	if m.createFn != nil {
		return m.createFn(ctx, client)
	}
	return nil
}
func (m *mockClients) Update(ctx context.Context, client *domain.Client) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, client)
	}
	return nil
}
func (m *mockClients) Delete(ctx context.Context, id uuid.UUID) error {
	return m.deleteFn(ctx, id)
}

func TestCreateClient_RequiresName(t *testing.T) {
	s := NewClientServer(&mockClients{})
	_, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{})
	assertStatusCode(t, err, codes.InvalidArgument)
}

func TestCreateClient_InvalidType(t *testing.T) {
	s := NewClientServer(&mockClients{})
	_, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{
		Name:       "n",
		ClientType: "nope",
	})
	assertStatusCode(t, err, codes.InvalidArgument)
}

func TestCreateClient_PublicNoSecret(t *testing.T) {
	repo := &mockClients{}
	s := NewClientServer(repo)
	resp, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{
		Name:       "spa",
		ClientType: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ClientSecret != "" {
		t.Fatalf("secret returned for public: %q", resp.ClientSecret)
	}
	if repo.lastCreate.ClientSecretHash != "" {
		t.Fatal("hash stored for public")
	}
	if resp.Client.ClientType != "public" {
		t.Fatalf("type: %q", resp.Client.ClientType)
	}
	if resp.Client.TokenEndpointAuthMethod != "none" {
		t.Fatalf("auth: %q", resp.Client.TokenEndpointAuthMethod)
	}
}

func TestCreateClient_AutoSecret(t *testing.T) {
	repo := &mockClients{}
	s := NewClientServer(repo)
	resp, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ClientSecret == "" {
		t.Fatal("expected plaintext secret once")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(repo.lastCreate.ClientSecretHash), []byte(resp.ClientSecret)); err != nil {
		t.Fatalf("hash mismatch: %v", err)
	}
	if resp.Client.ClientId == "" {
		t.Fatal("expected generated client_id")
	}
	if resp.Client.TenantId != domain.DefaultTenantID.String() {
		t.Fatalf("tenant: %q", resp.Client.TenantId)
	}
}

func TestCreateClient_ProvidedSecret(t *testing.T) {
	repo := &mockClients{}
	s := NewClientServer(repo)
	resp, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{
		Name:         "api",
		ClientId:     "fixed-id",
		ClientSecret: "provided-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ClientSecret != "provided-secret" {
		t.Fatalf("secret: %q", resp.ClientSecret)
	}
	if resp.Client.ClientId != "fixed-id" {
		t.Fatalf("client_id: %q", resp.Client.ClientId)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(repo.lastCreate.ClientSecretHash), []byte("provided-secret")); err != nil {
		t.Fatal(err)
	}
}

func TestCreateClient_RepoError(t *testing.T) {
	repo := &mockClients{createFn: func(context.Context, *domain.Client) error {
		return domain.ErrClientNotFound
	}}
	s := NewClientServer(repo)
	_, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{Name: "n"})
	assertStatusCode(t, err, codes.NotFound)
}

func TestGetClient(t *testing.T) {
	id := uuid.New()
	repo := &mockClients{getByID: func(_ context.Context, got uuid.UUID) (*domain.Client, error) {
		if got != id {
			t.Fatalf("id: %v", got)
		}
		return &domain.Client{
			ID:        id,
			TenantID:  domain.DefaultTenantID,
			ClientID:  "c",
			Name:      "n",
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}, nil
	}}
	s := NewClientServer(repo)

	_, err := s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: "bad"})
	assertStatusCode(t, err, codes.InvalidArgument)

	resp, err := s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: id.String()})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Client.Name != "n" {
		t.Fatalf("%#v", resp.Client)
	}

	repo.getByID = func(context.Context, uuid.UUID) (*domain.Client, error) {
		return nil, domain.ErrClientNotFound
	}
	_, err = s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: id.String()})
	assertStatusCode(t, err, codes.NotFound)
}

func TestListClients_DefaultLimit(t *testing.T) {
	repo := &mockClients{listFn: func(context.Context, uuid.UUID, repository.ClientFilter) ([]*domain.Client, error) {
		return nil, nil
	}}
	s := NewClientServer(repo)
	_, err := s.ListClients(context.Background(), &adminv1.ListClientsRequest{
		Search: "app",
		Offset: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if repo.lastFilter.Limit != 50 || repo.lastFilter.Offset != 10 || repo.lastFilter.Search != "app" {
		t.Fatalf("%#v", repo.lastFilter)
	}
	if repo.lastTenant != domain.DefaultTenantID {
		t.Fatalf("tenant %v", repo.lastTenant)
	}
}

func TestUpdateClient(t *testing.T) {
	id := uuid.New()
	existing := &domain.Client{
		ID:        id,
		TenantID:  domain.DefaultTenantID,
		ClientID:  "c",
		Name:      "old",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	repo := &mockClients{
		getByID: func(context.Context, uuid.UUID) (*domain.Client, error) { return existing, nil },
		updateFn: func(_ context.Context, c *domain.Client) error {
			if c.Name != "new" {
				t.Fatalf("name: %q", c.Name)
			}
			return nil
		},
	}
	s := NewClientServer(repo)

	_, err := s.UpdateClient(context.Background(), &adminv1.UpdateClientRequest{Id: "x"})
	assertStatusCode(t, err, codes.InvalidArgument)

	resp, err := s.UpdateClient(context.Background(), &adminv1.UpdateClientRequest{
		Id:   id.String(),
		Name: "new",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Client.Name != "new" {
		t.Fatalf("%q", resp.Client.Name)
	}
}

func TestDeleteClient(t *testing.T) {
	id := uuid.New()
	repo := &mockClients{deleteFn: func(_ context.Context, got uuid.UUID) error {
		if got != id {
			t.Fatalf("%v", got)
		}
		return nil
	}}
	s := NewClientServer(repo)

	_, err := s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: "bad"})
	assertStatusCode(t, err, codes.InvalidArgument)

	_, err = s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: id.String()})
	if err != nil {
		t.Fatal(err)
	}

	repo.deleteFn = func(context.Context, uuid.UUID) error { return domain.ErrClientNotFound }
	_, err = s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: id.String()})
	assertStatusCode(t, err, codes.NotFound)
}

var _ repository.ClientRepository = (*mockClients)(nil)
