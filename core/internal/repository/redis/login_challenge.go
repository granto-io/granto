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

// Key: {tenantID}:login_challenge:{id}

// LoginChallengeRepository is the Redis implementation of repository.LoginChallengeRepository.
type LoginChallengeRepository struct {
	rdb *goredis.Client
}

// NewLoginChallengeRepository constructs a login-challenge repository.
func NewLoginChallengeRepository(client *iredis.Client) *LoginChallengeRepository {
	return &LoginChallengeRepository{rdb: client.RDB()}
}

func loginChallengeKey(tenantID, id uuid.UUID) string {
	return tenantID.String() + ":login_challenge:" + id.String()
}

func (r *LoginChallengeRepository) Create(ctx context.Context, c *domain.LoginChallenge) error {
	if c == nil {
		return fmt.Errorf("login challenge is nil")
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
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("login challenge already expired")
	}

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal login challenge: %w", err)
	}
	if err := r.rdb.Set(ctx, loginChallengeKey(c.TenantID, c.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("store login challenge: %w", err)
	}
	return nil
}

func (r *LoginChallengeRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.LoginChallenge, error) {
	c, err := r.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if c.IsExpired() {
		_ = r.rdb.Del(ctx, loginChallengeKey(tenantID, id)).Err()
		return nil, domain.ErrLoginChallengeExpired
	}
	return c, nil
}

func (r *LoginChallengeRepository) Consume(ctx context.Context, tenantID, id uuid.UUID, opts repository.ChallengeConsumeOpts) (*domain.LoginChallenge, error) {
	c, err := r.load(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if c.IsExpired() {
		_ = r.rdb.Del(ctx, loginChallengeKey(tenantID, id)).Err()
		return nil, domain.ErrLoginChallengeExpired
	}
	if opts.RequireToken || opts.AcceptToken != "" {
		if !c.ValidAcceptToken(opts.AcceptToken) {
			return nil, domain.ErrLoginChallengeAcceptTokenInvalid
		}
	}
	if err := r.rdb.Del(ctx, loginChallengeKey(tenantID, id)).Err(); err != nil {
		return nil, fmt.Errorf("delete login challenge after consume: %w", err)
	}
	return c, nil
}

func (r *LoginChallengeRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.rdb.Del(ctx, loginChallengeKey(tenantID, id)).Result()
	if err != nil {
		return fmt.Errorf("delete login challenge: %w", err)
	}
	if n == 0 {
		return domain.ErrLoginChallengeNotFound
	}
	return nil
}

func (r *LoginChallengeRepository) load(ctx context.Context, tenantID, id uuid.UUID) (*domain.LoginChallenge, error) {
	data, err := r.rdb.Get(ctx, loginChallengeKey(tenantID, id)).Bytes()
	if err == goredis.Nil {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get login challenge: %w", err)
	}
	var c domain.LoginChallenge
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("unmarshal login challenge: %w", err)
	}
	return &c, nil
}
