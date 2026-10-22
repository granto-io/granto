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

// LoginSessionServer implements adminv1.LoginSessionServiceServer.
type LoginSessionServer struct {
	adminv1.UnimplementedLoginSessionServiceServer
	flow *oauth2.Flow
}

// NewLoginSessionServer constructs an Admin LoginSessionService.
func NewLoginSessionServer(flow *oauth2.Flow) *LoginSessionServer {
	return &LoginSessionServer{flow: flow}
}

func (s *LoginSessionServer) GetLoginSession(ctx context.Context, req *adminv1.GetLoginSessionRequest) (*adminv1.GetLoginSessionResponse, error) {
	sess, err := s.flow.GetLoginSession(ctx, req.GetId())
	if err != nil {
		return nil, sessionErrToStatus(err)
	}
	return &adminv1.GetLoginSessionResponse{Session: loginSessionToProto(sess)}, nil
}

func (s *LoginSessionServer) ListLoginSessions(ctx context.Context, req *adminv1.ListLoginSessionsRequest) (*adminv1.ListLoginSessionsResponse, error) {
	list, err := s.flow.ListLoginSessions(ctx, req.GetSubject())
	if err != nil {
		return nil, sessionErrToStatus(err)
	}
	out := make([]*adminv1.LoginSession, 0, len(list))
	for _, sess := range list {
		out = append(out, loginSessionToProto(sess))
	}
	return &adminv1.ListLoginSessionsResponse{Sessions: out}, nil
}

func (s *LoginSessionServer) DeleteLoginSession(ctx context.Context, req *adminv1.DeleteLoginSessionRequest) (*adminv1.DeleteLoginSessionResponse, error) {
	if err := s.flow.DeleteLoginSession(ctx, req.GetId()); err != nil {
		return nil, sessionErrToStatus(err)
	}
	return &adminv1.DeleteLoginSessionResponse{}, nil
}

func (s *LoginSessionServer) RevokeLoginSessions(ctx context.Context, req *adminv1.RevokeLoginSessionsRequest) (*adminv1.RevokeLoginSessionsResponse, error) {
	if err := s.flow.RevokeLoginSessions(ctx, req.GetSubject(), req.GetSid()); err != nil {
		return nil, sessionErrToStatus(err)
	}
	return &adminv1.RevokeLoginSessionsResponse{}, nil
}

func loginSessionToProto(s *domain.LoginSession) *adminv1.LoginSession {
	if s == nil {
		return nil
	}
	amr := s.AMR
	if amr == nil {
		amr = []string{}
	}
	return &adminv1.LoginSession{
		Id:                        s.ID.String(),
		TenantId:                  s.TenantID.String(),
		Subject:                   s.Subject,
		AuthenticatedAt:           timestamppb.New(s.AuthenticatedAt),
		ExpiresAt:                 timestamppb.New(s.ExpiresAt),
		Remember:                  s.Remember,
		DeviceId:                  s.DeviceID,
		Acr:                       s.ACR,
		Amr:                       amr,
		IdentityProviderSessionId: s.IdentityProviderSessionID,
		Metadata:                  mapToStructpb(s.Metadata),
		CreatedAt:                 timestamppb.New(s.CreatedAt),
		UpdatedAt:                 timestamppb.New(s.UpdatedAt),
	}
}

func sessionErrToStatus(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, oauth2.ErrInvalidRequest) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return domainErrToStatus(err)
}
