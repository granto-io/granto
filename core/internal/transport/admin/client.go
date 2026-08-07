package admin

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
)

// ClientServer implements adminv1.ClientServiceServer.
type ClientServer struct {
	adminv1.UnimplementedClientServiceServer
	clients repository.ClientRepository
}

// NewClientServer constructs an Admin ClientService backed by the client repository.
func NewClientServer(clients repository.ClientRepository) *ClientServer {
	return &ClientServer{clients: clients}
}

func (s *ClientServer) CreateClient(ctx context.Context, req *adminv1.CreateClientRequest) (*adminv1.CreateClientResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:        uuid.New(),
		TenantID:  tenantIDFromStr(req.GetTenantId()),
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

	var (
		rawSecret string
		err       error
	)
	if client.ClientType != domain.ClientTypePublic {
		if req.GetClientSecret() != "" {
			client.ClientSecretHash, err = hashClientSecret(req.GetClientSecret())
			if err != nil {
				return nil, status.Errorf(codes.Internal, "hash secret: %v", err)
			}
			rawSecret = req.GetClientSecret()
		} else {
			rawSecret, client.ClientSecretHash, err = newClientSecret()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "generate secret: %v", err)
			}
		}
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, domainErrToStatus(err)
	}

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
	client, err := s.clients.GetByID(ctx, id)
	if err != nil {
		return nil, domainErrToStatus(err)
	}
	return &adminv1.GetClientResponse{Client: clientToProto(client)}, nil
}

func (s *ClientServer) ListClients(ctx context.Context, req *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}

	clients, err := s.clients.List(ctx, tenantIDFromStr(req.GetTenantId()), repository.ClientFilter{
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
	client, err := s.clients.GetByID(ctx, id)
	if err != nil {
		return nil, domainErrToStatus(err)
	}

	if err := applyClientBody(client, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	client.UpdatedAt = time.Now().UTC()

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, domainErrToStatus(err)
	}
	return &adminv1.UpdateClientResponse{Client: clientToProto(client)}, nil
}

func (s *ClientServer) DeleteClient(ctx context.Context, req *adminv1.DeleteClientRequest) (*adminv1.DeleteClientResponse, error) {
	id, err := parseUUID(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "id must be a UUID")
	}
	if err := s.clients.Delete(ctx, id); err != nil {
		return nil, domainErrToStatus(err)
	}
	return &adminv1.DeleteClientResponse{}, nil
}
