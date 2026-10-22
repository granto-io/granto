package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
	"github.com/granto-io/granto/core/internal/reqmeta"
)

// ClientServer implements adminv1.ClientServiceServer.
type ClientServer struct {
	adminv1.UnimplementedClientServiceServer
	clients repository.ClientRepository
	audit   repository.AuditRepository
}

// NewClientServer constructs an Admin ClientService backed by the client repository.
func NewClientServer(clients repository.ClientRepository, audit repository.AuditRepository) *ClientServer {
	return &ClientServer{clients: clients, audit: audit}
}

func (s *ClientServer) CreateClient(ctx context.Context, req *adminv1.CreateClientRequest) (*adminv1.CreateClientResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	tenantID, err := resolveRequestTenant(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:        uuid.New(),
		TenantID:  tenantID,
		IsDynamic: false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := applyClientBody(client, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	applyClientCreateDefaults(client)

	clientID := req.GetClientId()
	if clientID == "" {
		clientID = uuid.New().String()
	}
	client.ClientID = clientID

	var rawSecret string
	if client.ClientType != domain.ClientTypePublic {
		if req.GetClientSecret() != "" {
			client.ClientSecretHash, err = hashClientSecret(req.GetClientSecret())
			if err != nil {
				return nil, internalStatus(fmt.Errorf("hash secret: %w", err))
			}
			rawSecret = req.GetClientSecret()
		} else {
			rawSecret, client.ClientSecretHash, err = newClientSecret()
			if err != nil {
				return nil, internalStatus(fmt.Errorf("generate secret: %w", err))
			}
		}
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, domainErrToStatus(err)
	}
	s.logClientAudit(ctx, domain.AuditEventClientCreated, client)

	return &adminv1.CreateClientResponse{
		Client:       clientToProto(client),
		ClientSecret: rawSecret,
	}, nil
}

func (s *ClientServer) GetClient(ctx context.Context, req *adminv1.GetClientRequest) (*adminv1.GetClientResponse, error) {
	id, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id must be a UUID")
	}
	client, err := s.clients.GetByID(ctx, authTenantID(ctx), id)
	if err != nil {
		return nil, domainErrToStatus(err)
	}
	return &adminv1.GetClientResponse{Client: clientToProto(client)}, nil
}

func (s *ClientServer) ListClients(ctx context.Context, req *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	tenantID, err := resolveRequestTenant(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}

	clients, err := s.clients.List(ctx, tenantID, repository.ClientFilter{
		Limit:  limit,
		Offset: int(req.GetOffset()),
		Search: req.GetSearch(),
	})
	if err != nil {
		return nil, domainErrToStatus(err)
	}

	out := make([]*adminv1.Client, len(clients))
	for i, c := range clients {
		out[i] = clientToProto(c)
	}
	return &adminv1.ListClientsResponse{Clients: out}, nil
}

func (s *ClientServer) UpdateClient(ctx context.Context, req *adminv1.UpdateClientRequest) (*adminv1.UpdateClientResponse, error) {
	id, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id must be a UUID")
	}
	tenantID := authTenantID(ctx)
	client, err := s.clients.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, domainErrToStatus(err)
	}

	if err := applyClientBody(client, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Never allow body/mapper to reassign tenant.
	client.TenantID = tenantID
	client.UpdatedAt = time.Now().UTC()

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, domainErrToStatus(err)
	}
	s.logClientAudit(ctx, domain.AuditEventClientUpdated, client)
	return &adminv1.UpdateClientResponse{Client: clientToProto(client)}, nil
}

func (s *ClientServer) DeleteClient(ctx context.Context, req *adminv1.DeleteClientRequest) (*adminv1.DeleteClientResponse, error) {
	id, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id must be a UUID")
	}
	tenantID := authTenantID(ctx)
	client, err := s.clients.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, domainErrToStatus(err)
	}
	if err := s.clients.Delete(ctx, tenantID, id); err != nil {
		return nil, domainErrToStatus(err)
	}
	s.logClientAudit(ctx, domain.AuditEventClientDeleted, client)
	return &adminv1.DeleteClientResponse{}, nil
}

func (s *ClientServer) logClientAudit(ctx context.Context, eventType string, client *domain.Client) {
	if s.audit == nil || client == nil {
		return
	}
	e := &domain.AuditEvent{
		TenantID:    client.TenantID,
		EventType:   eventType,
		ActorType:   domain.AuditActorAdmin,
		ActorID:     "",
		SubjectType: domain.AuditSubjectClient,
		SubjectID:   client.ClientID,
		ClientID:    client.ClientID,
		Outcome:     domain.AuditOutcomeSuccess,
		Metadata:    map[string]any{"source": "admin"},
	}
	if ip := reqmeta.IP(ctx); ip != nil {
		e.IPAddress = ip
	}
	if ua := reqmeta.UserAgent(ctx); ua != "" {
		e.UserAgent = ua
	}
	_ = s.audit.Log(ctx, e)
}
