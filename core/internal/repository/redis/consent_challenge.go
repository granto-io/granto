package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/granto-io/granto/core/internal/domain"
	iredis "github.com/granto-io/granto/core/internal/redis"
	"github.com/granto-io/granto/core/internal/repository"
)

// Key: {tenantID}:consent_challenge:{id}

// ConsentChallengeRepository is the Redis implementation of repository.ConsentChallengeRepository.
type ConsentChallengeRepository struct {
	rdb *goredis.Client
}

// NewConsentChallengeRepository constructs a consent-challenge repository.
func NewConsentChallengeRepository(client *iredis.Client) *ConsentChallengeRepository {
	return &ConsentChallengeRepository{rdb: client.RDB()}
}

func consentChallengeKey(tenantID, id uuid.UUID) string {
	return tenantID.String() + ":consent_challenge:" + id.String()
}

func (r *ConsentChallengeRepository) Create(ctx context.Context, c *domain.ConsentChallenge) error {
	if c == nil {
		return fmt.Errorf("consent challenge is nil")
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.AcceptToken == "" {
		tok, err := domain.NewAcceptToken()
		if err != nil {
			return fmt.Errorf("generate accept token: %w", err)
		}
		c.AcceptToken = tok
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.AMR == nil {
		c.AMR = []string{}
	}
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("consent challenge already expired")
	}

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal consent challenge: %w", err)
	}
	if err := r.rdb.Set(ctx, consentChallengeKey(c.TenantID, c.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("store consent challenge: %w", err)
	}
	return nil
}

func (r *ConsentChallengeRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.ConsentChallenge, error) {
	c, err := r.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if c.IsExpired() {
		_ = r.rdb.Del(ctx, consentChallengeKey(tenantID, id)).Err()
		return nil, domain.ErrConsentChallengeExpired
	}
	return c, nil
}

func (r *ConsentChallengeRepository) Consume(ctx context.Context, tenantID, id uuid.UUID, opts repository.ChallengeConsumeOpts) (*domain.ConsentChallenge, error) {
	c, err := r.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if c.IsExpired() {
		_ = r.rdb.Del(ctx, consentChallengeKey(tenantID, id)).Err()
		return nil, domain.ErrConsentChallengeExpired
	}
	if opts.RequireToken || opts.AcceptToken != "" {
		if !c.ValidAcceptToken(opts.AcceptToken) {
			return nil, domain.ErrConsentChallengeAcceptTokenInvalid
		}
	}
	if err := r.rdb.Del(ctx, consentChallengeKey(tenantID, id)).Err(); err != nil {
		return nil, fmt.Errorf("delete consent challenge after consume: %w", err)
	}
	return c, nil
}

func (r *ConsentChallengeRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.rdb.Del(ctx, consentChallengeKey(tenantID, id)).Result()
	if err != nil {
		return fmt.Errorf("delete consent challenge: %w", err)
	}
	if n == 0 {
		return domain.ErrConsentChallengeNotFound
	}
	return nil
}

func (r *ConsentChallengeRepository) load(ctx context.Context, tenantID, id uuid.UUID) (*domain.ConsentChallenge, error) {
	data, err := r.rdb.Get(ctx, consentChallengeKey(tenantID, id)).Bytes()
	if err == goredis.Nil {
		return nil, domain.ErrConsentChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get consent challenge: %w", err)
	}
	var c domain.ConsentChallenge
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("unmarshal consent challenge: %w", err)
	}
	return &c, nil
}
