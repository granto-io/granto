package admin

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

// ConsentGrantServer implements adminv1.ConsentGrantServiceServer.
type ConsentGrantServer struct {
	adminv1.UnimplementedConsentGrantServiceServer
	flow *oauth2.Flow
}

// NewConsentGrantServer constructs an Admin ConsentGrantService.
func NewConsentGrantServer(flow *oauth2.Flow) *ConsentGrantServer {
	return &ConsentGrantServer{flow: flow}
}

func (s *ConsentGrantServer) ListConsentGrants(ctx context.Context, req *adminv1.ListConsentGrantsRequest) (*adminv1.ListConsentGrantsResponse, error) {
	list, err := s.flow.ListConsentGrants(ctx, req.GetSubject(), req.GetClientId())
	if err != nil {
		return nil, consentGrantErrToStatus(err)
	}
	out := make([]*adminv1.ConsentGrant, 0, len(list))
	for _, g := range list {
		out = append(out, consentGrantToProto(g))
	}
	return &adminv1.ListConsentGrantsResponse{Grants: out}, nil
}

func (s *ConsentGrantServer) RevokeConsentGrants(ctx context.Context, req *adminv1.RevokeConsentGrantsRequest) (*adminv1.RevokeConsentGrantsResponse, error) {
	if err := s.flow.RevokeConsentGrants(ctx, req.GetSubject(), req.GetClientId()); err != nil {
		return nil, consentGrantErrToStatus(err)
	}
	return &adminv1.RevokeConsentGrantsResponse{}, nil
}

func consentGrantToProto(g *domain.ConsentGrant) *adminv1.ConsentGrant {
	if g == nil {
		return nil
	}
	scopes := g.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	audience := g.Audience
	if audience == nil {
		audience = []string{}
	}
	out := &adminv1.ConsentGrant{
		Id:        g.ID.String(),
		TenantId:  g.TenantID.String(),
		Subject:   g.Subject,
		ClientId:  g.ClientID,
		Scopes:    scopes,
		Audience:  audience,
		CreatedAt: timestamppb.New(g.CreatedAt),
		UpdatedAt: timestamppb.New(g.UpdatedAt),
	}
	if g.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*g.ExpiresAt)
	}
	return out
}

func consentGrantErrToStatus(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, oauth2.ErrInvalidRequest) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return domainErrToStatus(err)
}
