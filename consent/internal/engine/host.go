package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

// host implements pluginapi.Host for one plugin.
type host struct {
	engine *Engine
	router chi.Router
	config *yaml.Node
	logger *slog.Logger
}

func (h *host) Logger() *slog.Logger { return h.logger }

func (h *host) Config() *yaml.Node { return h.config }

func (h *host) Router() chi.Router { return h.router }

func (h *host) Identity() pluginapi.IdentityClient { return h.engine.identity }

func (h *host) CSRFToken(challengeID string) string {
	return h.engine.csrf.Token(challengeID)
}

func (h *host) VerifyCSRF(challengeID, token string) error {
	if err := h.engine.csrf.Verify(challengeID, token); err != nil {
		return fmt.Errorf("%w: %v", pluginapi.ErrInvalidCSRF, err)
	}
	return nil
}

func (h *host) GetLogin(ctx context.Context, challengeID string) (*pluginapi.LoginRequest, error) {
	req, err := h.engine.admin.GetLogin(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	return &pluginapi.LoginRequest{
		ChallengeID: req.ChallengeID,
		ClientID:    req.ClientID,
		LoginHint:   req.LoginHint,
		Subject:     req.Subject,
	}, nil
}

func (h *host) CompleteLogin(ctx context.Context, in pluginapi.LoginCompletion) (string, error) {
	if err := h.VerifyCSRF(in.ChallengeID, in.CSRFToken); err != nil {
		return "", err
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		return "", pluginapi.ErrMissingSubject
	}

	// Re-read the challenge to obtain accept_token for strict accept mode and
	// to make sure it is still pending.
	req, err := h.engine.admin.GetLogin(ctx, in.ChallengeID)
	if err != nil {
		return "", err
	}
	redirect, err := h.engine.admin.AcceptLogin(ctx, adminclient.AcceptLoginInput{
		ChallengeID:               in.ChallengeID,
		Subject:                   subject,
		Remember:                  in.Remember,
		RememberFor:               in.RememberFor,
		ACR:                       in.ACR,
		AMR:                       in.AMR,
		Context:                   in.Context,
		IdentityProviderSessionID: in.IdentityProviderSessionID,
		AcceptToken:               req.AcceptToken,
	})
	if err != nil {
		return "", err
	}
	if redirect == "" {
		return "", fmt.Errorf("engine: core returned an empty redirect")
	}
	return redirect, nil
}

func (h *host) RejectLogin(ctx context.Context, in pluginapi.LoginRejection) (string, error) {
	if err := h.VerifyCSRF(in.ChallengeID, in.CSRFToken); err != nil {
		return "", err
	}
	req, err := h.engine.admin.GetLogin(ctx, in.ChallengeID)
	if err != nil {
		return "", err
	}
	redirect, err := h.engine.admin.RejectLogin(ctx, adminclient.RejectInput{
		ChallengeID:      in.ChallengeID,
		Error:            in.Error,
		ErrorDescription: in.ErrorDescription,
		ErrorHint:        in.ErrorHint,
		AcceptToken:      req.AcceptToken,
	})
	if err != nil {
		return "", err
	}
	if redirect == "" {
		return "", fmt.Errorf("engine: core returned an empty redirect")
	}
	return redirect, nil
}
