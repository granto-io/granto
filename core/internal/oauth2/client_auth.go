package oauth2

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/domain"
)

// dummyClientSecretHash is a real bcrypt hash used only to equalize timing when
// the client is unknown or has no stored secret. Without this, missing client_id
// returns in ~DB RTT while a confidential client burns tens of ms in bcrypt —
// enough to enumerate valid client_id on token/revoke/introspect.
var (
	dummyClientSecretHash     []byte
	dummyClientSecretHashOnce sync.Once
)

func clientSecretDummyHash() []byte {
	dummyClientSecretHashOnce.Do(func() {
		h, err := bcrypt.GenerateFromPassword([]byte("granto-dummy-client-secret"), bcrypt.DefaultCost)
		if err != nil {
			// bcrypt.DefaultCost must always succeed with a short plaintext.
			panic("oauth2: generate dummy client secret hash: " + err.Error())
		}
		dummyClientSecretHash = h
	})
	return dummyClientSecretHash
}

func (f *Flow) authenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if clientID == "" {
		f.auditTokenFailure(ctx, "", "invalid_client", map[string]any{"reason": "missing_client_id"})
		return nil, ErrInvalidClient
	}
	client, err := f.clients.GetByClientID(ctx, f.tenantID(), clientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			// Same work as a failed confidential check (timing side-channel).
			_ = verifyClientSecret(clientSecretDummyHash(), clientSecret)
			f.auditTokenFailure(ctx, clientID, "invalid_client", map[string]any{"reason": "unknown_client"})
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	if client.IsPublic() || client.TokenEndpointAuthMethod == domain.TokenEndpointAuthNone {
		return client, nil
	}

	hash := []byte(client.ClientSecretHash)
	if len(hash) == 0 {
		hash = clientSecretDummyHash()
	}
	if err := verifyClientSecret(hash, clientSecret); err != nil {
		f.auditTokenFailure(ctx, clientID, "invalid_client", map[string]any{"reason": "bad_client_secret"})
		return nil, ErrInvalidClientSecret
	}
	return client, nil
}

func verifyClientSecret(hash []byte, secret string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(secret))
}
