package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

// OAuth2Server implements adminv1.OAuth2ServiceServer.
type OAuth2Server struct {
	adminv1.UnimplementedOAuth2ServiceServer
	flow *oauth2.Flow
}

// NewOAuth2Server constructs an Admin OAuth2Service backed by the flow orchestrator.
func NewOAuth2Server(flow *oauth2.Flow) *OAuth2Server {
	return &OAuth2Server{flow: flow}
}

func (s *OAuth2Server) GetLoginRequest(ctx context.Context, req *adminv1.GetLoginRequestRequest) (*adminv1.GetLoginRequestResponse, error) {
	out, err := s.flow.GetLogin(ctx, req.GetLoginChallenge())
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	ch := out.Challenge
	return &adminv1.GetLoginRequestResponse{
		Challenge:                    ch.ID.String(),
		ClientId:                     ch.ClientID,
		RequestUrl:                   ch.RequestURL,
		RedirectUri:                  ch.RedirectURI,
		RequestedScope:               ch.RequestedScopes,
		RequestedAccessTokenAudience: ch.RequestedAudience,
		Skip:                         ch.Skip,
		Subject:                      out.Subject,
		SessionId:                    uuidString(ch.SessionID),
		OidcContext:                  oidcContextToProto(ch.OIDCContext),
		AcceptToken:                  ch.AcceptToken,
	}, nil
}

func (s *OAuth2Server) AcceptLoginRequest(ctx context.Context, req *adminv1.AcceptLoginRequestRequest) (*adminv1.OAuth2RedirectTo, error) {
	body := req.GetBody()
	if body == nil {
		return nil, status.Error(codes.InvalidArgument, "body is required")
	}
	redirect, err := s.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID:               req.GetLoginChallenge(),
		Subject:                   body.GetSubject(),
		Remember:                  body.GetRemember(),
		RememberFor:               body.GetRememberFor(),
		ACR:                       body.GetAcr(),
		AMR:                       body.GetAmr(),
		Context:                   structToMap(body.GetContext()),
		IdentityProviderSessionID: body.GetIdentityProviderSessionId(),
		AcceptToken:               body.GetAcceptToken(),
	})
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	return &adminv1.OAuth2RedirectTo{RedirectTo: redirect}, nil
}

func (s *OAuth2Server) RejectLoginRequest(ctx context.Context, req *adminv1.RejectLoginRequestRequest) (*adminv1.OAuth2RedirectTo, error) {
	body := req.GetBody()
	in := oauth2.RejectInput{ChallengeID: req.GetLoginChallenge()}
	if body != nil {
		in.Error = body.GetError()
		in.ErrorDescription = body.GetErrorDescription()
		in.ErrorHint = body.GetErrorHint()
		in.AcceptToken = body.GetAcceptToken()
	}
	redirect, err := s.flow.RejectLogin(ctx, in)
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	return &adminv1.OAuth2RedirectTo{RedirectTo: redirect}, nil
}

func (s *OAuth2Server) GetConsentRequest(ctx context.Context, req *adminv1.GetConsentRequestRequest) (*adminv1.GetConsentRequestResponse, error) {
	out, err := s.flow.GetConsent(ctx, req.GetConsentChallenge())
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	ch := out.Challenge
	return &adminv1.GetConsentRequestResponse{
		Challenge:                    ch.ID.String(),
		ClientId:                     ch.ClientID,
		RequestUrl:                   ch.RequestURL,
		RedirectUri:                  ch.RedirectURI,
		RequestedScope:               ch.RequestedScopes,
		RequestedAccessTokenAudience: ch.RequestedAudience,
		Skip:                         ch.Skip,
		Subject:                      ch.Subject,
		SessionId:                    uuidString(ch.SessionID),
		LoginChallenge:               uuidString(ch.LoginChallengeID),
		Acr:                          ch.ACR,
		Amr:                          ch.AMR,
		Context:                      mapToStruct(ch.Context),
		OidcContext:                  oidcContextToProto(ch.OIDCContext),
		AcceptToken:                  ch.AcceptToken,
	}, nil
}

func (s *OAuth2Server) AcceptConsentRequest(ctx context.Context, req *adminv1.AcceptConsentRequestRequest) (*adminv1.OAuth2RedirectTo, error) {
	body := req.GetBody()
	if body == nil {
		return nil, status.Error(codes.InvalidArgument, "body is required")
	}
	var access, idTok map[string]any
	if sess := body.GetSession(); sess != nil {
		access = structToMap(sess.GetAccessToken())
		idTok = structToMap(sess.GetIdToken())
	}
	redirect, err := s.flow.AcceptConsent(ctx, oauth2.AcceptConsentInput{
		ChallengeID:    req.GetConsentChallenge(),
		GrantScope:     body.GetGrantScope(),
		GrantAudience:  body.GetGrantAccessTokenAudience(),
		Remember:       body.GetRemember(),
		RememberFor:    body.GetRememberFor(),
		SessionAccess:  access,
		SessionIDToken: idTok,
		Context:        structToMap(body.GetContext()),
		AcceptToken:    body.GetAcceptToken(),
	})
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	return &adminv1.OAuth2RedirectTo{RedirectTo: redirect}, nil
}

func (s *OAuth2Server) RejectConsentRequest(ctx context.Context, req *adminv1.RejectConsentRequestRequest) (*adminv1.OAuth2RedirectTo, error) {
	body := req.GetBody()
	in := oauth2.RejectInput{ChallengeID: req.GetConsentChallenge()}
	if body != nil {
		in.Error = body.GetError()
		in.ErrorDescription = body.GetErrorDescription()
		in.ErrorHint = body.GetErrorHint()
		in.AcceptToken = body.GetAcceptToken()
	}
	redirect, err := s.flow.RejectConsent(ctx, in)
	if err != nil {
		return nil, oauth2ErrToStatus(err)
	}
	return &adminv1.OAuth2RedirectTo{RedirectTo: redirect}, nil
}

func oidcContextToProto(c domain.OIDCContext) *adminv1.OIDCContext {
	return &adminv1.OIDCContext{
		AcrValues:         c.ACRValues,
		UiLocales:         c.UILocales,
		Display:           c.Display,
		LoginHint:         c.LoginHint,
		IdTokenHintClaims: mapToStruct(c.IDTokenHintClaims),
	}
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

func mapToStruct(m map[string]any) *structpb.Struct {
	if m == nil {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}
