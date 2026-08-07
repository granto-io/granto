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
		t.Fatalf("CreateClient(public) unexpected error: %v", err)
	}
	if resp.ClientSecret != "" {
		t.Fatalf("ClientSecret = %q, want empty for public client", resp.ClientSecret)
	}
	if repo.lastCreate.ClientSecretHash != "" {
		t.Fatalf("persisted ClientSecretHash = %q, want empty for public client", repo.lastCreate.ClientSecretHash)
	}
	if resp.Client.ClientType != "public" {
		t.Fatalf("Client.ClientType = %q, want %q", resp.Client.ClientType, "public")
	}
	if resp.Client.TokenEndpointAuthMethod != "none" {
		t.Fatalf("Client.TokenEndpointAuthMethod = %q, want %q", resp.Client.TokenEndpointAuthMethod, "none")
	}
}

func TestCreateClient_AutoSecret(t *testing.T) {
	repo := &mockClients{}
	s := NewClientServer(repo)
	resp, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{Name: "api"})
	if err != nil {
		t.Fatalf("CreateClient unexpected error: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Fatalf("ClientSecret is empty, want generated plaintext returned once")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(repo.lastCreate.ClientSecretHash), []byte(resp.ClientSecret)); err != nil {
		t.Fatalf("persisted hash does not match returned ClientSecret: %v", err)
	}
	if resp.Client.ClientId == "" {
		t.Fatalf("Client.ClientId is empty, want auto-generated UUID string")
	}
	wantTenant := domain.DefaultTenantID.String()
	if resp.Client.TenantId != wantTenant {
		t.Fatalf("Client.TenantId = %q, want default tenant %q", resp.Client.TenantId, wantTenant)
	}
}

func TestCreateClient_ProvidedSecret(t *testing.T) {
	repo := &mockClients{}
	s := NewClientServer(repo)
	const (
		wantID     = "fixed-id"
		wantSecret = "provided-secret"
	)
	resp, err := s.CreateClient(context.Background(), &adminv1.CreateClientRequest{
		Name:         "api",
		ClientId:     wantID,
		ClientSecret: wantSecret,
	})
	if err != nil {
		t.Fatalf("CreateClient unexpected error: %v", err)
	}
	if resp.ClientSecret != wantSecret {
		t.Fatalf("ClientSecret = %q, want provided %q", resp.ClientSecret, wantSecret)
	}
	if resp.Client.ClientId != wantID {
		t.Fatalf("Client.ClientId = %q, want %q", resp.Client.ClientId, wantID)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(repo.lastCreate.ClientSecretHash), []byte(wantSecret)); err != nil {
		t.Fatalf("persisted hash does not match provided secret %q: %v", wantSecret, err)
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
			t.Fatalf("GetByID called with id=%v, want %v", got, id)
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

	t.Run("invalid uuid is invalid argument", func(t *testing.T) {
		_, err := s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: "bad"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("existing client", func(t *testing.T) {
		resp, err := s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: id.String()})
		if err != nil {
			t.Fatalf("GetClient unexpected error: %v", err)
		}
		if resp.Client.Name != "n" {
			t.Fatalf("Client.Name = %q, want %q", resp.Client.Name, "n")
		}
	})

	t.Run("missing client is not found", func(t *testing.T) {
		repo.getByID = func(context.Context, uuid.UUID) (*domain.Client, error) {
			return nil, domain.ErrClientNotFound
		}
		_, err := s.GetClient(context.Background(), &adminv1.GetClientRequest{Id: id.String()})
		assertStatusCode(t, err, codes.NotFound)
	})
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
		t.Fatalf("ListClients unexpected error: %v", err)
	}
	if repo.lastFilter.Limit != 50 {
		t.Fatalf("filter.Limit = %d, want default 50 when request limit is unset", repo.lastFilter.Limit)
	}
	if repo.lastFilter.Offset != 10 {
		t.Fatalf("filter.Offset = %d, want %d", repo.lastFilter.Offset, 10)
	}
	if repo.lastFilter.Search != "app" {
		t.Fatalf("filter.Search = %q, want %q", repo.lastFilter.Search, "app")
	}
	if repo.lastTenant != domain.DefaultTenantID {
		t.Fatalf("tenantID = %v, want DefaultTenantID %v", repo.lastTenant, domain.DefaultTenantID)
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
				t.Fatalf("Update called with Name=%q, want %q", c.Name, "new")
			}
			return nil
		},
	}
	s := NewClientServer(repo)

	t.Run("invalid uuid is invalid argument", func(t *testing.T) {
		_, err := s.UpdateClient(context.Background(), &adminv1.UpdateClientRequest{Id: "x"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("updates name", func(t *testing.T) {
		resp, err := s.UpdateClient(context.Background(), &adminv1.UpdateClientRequest{
			Id:   id.String(),
			Name: "new",
		})
		if err != nil {
			t.Fatalf("UpdateClient unexpected error: %v", err)
		}
		if resp.Client.Name != "new" {
			t.Fatalf("Client.Name = %q, want %q", resp.Client.Name, "new")
		}
	})
}

func TestDeleteClient(t *testing.T) {
	id := uuid.New()
	repo := &mockClients{deleteFn: func(_ context.Context, got uuid.UUID) error {
		if got != id {
			t.Fatalf("Delete called with id=%v, want %v", got, id)
		}
		return nil
	}}
	s := NewClientServer(repo)

	t.Run("invalid uuid is invalid argument", func(t *testing.T) {
		_, err := s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: "bad"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		_, err := s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: id.String()})
		if err != nil {
			t.Fatalf("DeleteClient unexpected error: %v", err)
		}
	})

	t.Run("missing client is not found", func(t *testing.T) {
		repo.deleteFn = func(context.Context, uuid.UUID) error { return domain.ErrClientNotFound }
		_, err := s.DeleteClient(context.Background(), &adminv1.DeleteClientRequest{Id: id.String()})
		assertStatusCode(t, err, codes.NotFound)
	})
}

var _ repository.ClientRepository = (*mockClients)(nil)
