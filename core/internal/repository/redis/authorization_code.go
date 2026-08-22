package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/granto-io/granto/core/internal/domain"
	iredis "github.com/granto-io/granto/core/internal/redis"
)

// Keys:
//
//	{tenantID}:authorization_code:{codeHash}       → JSON
//	{tenantID}:authorization_code_used:{codeHash}  → "1" (replay sentinel)

// consumeAuthorizationCodeScript atomically checks the used sentinel, fetches
// the code, sets the sentinel with the remaining TTL, and deletes the code.
// KEYS[1] = used key, KEYS[2] = code key
var consumeAuthorizationCodeScript = goredis.NewScript(`
local used_key = KEYS[1]
local code_key = KEYS[2]
if redis.call('EXISTS', used_key) == 1 then
  return redis.error_reply('already_used')
end
local data = redis.call('GET', code_key)
if not data then
  return false
end
local ttl = redis.call('TTL', code_key)
if ttl < 0 then ttl = 600 end
redis.call('SET', used_key, '1', 'EX', ttl)
redis.call('DEL', code_key)
return data
`)

// AuthorizationCodeRepository is the Redis implementation of repository.AuthorizationCodeRepository.
type AuthorizationCodeRepository struct {
	rdb *goredis.Client
}

// NewAuthorizationCodeRepository constructs an authorization-code repository.
func NewAuthorizationCodeRepository(client *iredis.Client) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{rdb: client.RDB()}
}

func authorizationCodeKey(tenantID uuid.UUID, codeHash string) string {
	return tenantID.String() + ":authorization_code:" + codeHash
}

func authorizationCodeUsedKey(tenantID uuid.UUID, codeHash string) string {
	return tenantID.String() + ":authorization_code_used:" + codeHash
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, c *domain.AuthorizationCode) error {
	if c == nil {
		return fmt.Errorf("authorization code is nil")
	}
	if c.CodeHash == "" {
		return fmt.Errorf("authorization code hash is empty")
	}
	if c.ClientID == "" || c.Subject == "" || c.RedirectURI == "" {
		return fmt.Errorf("authorization code missing client_id, subject, or redirect_uri")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	if c.Audience == nil {
		c.Audience = []string{}
	}
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("authorization code already expired")
	}

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal authorization code: %w", err)
	}
	if err := r.rdb.Set(ctx, authorizationCodeKey(c.TenantID, c.CodeHash), data, ttl).Err(); err != nil {
		return fmt.Errorf("store authorization code: %w", err)
	}
	return nil
}

func (r *AuthorizationCodeRepository) Consume(ctx context.Context, tenantID uuid.UUID, codeHash string) (*domain.AuthorizationCode, error) {
	usedKey := authorizationCodeUsedKey(tenantID, codeHash)
	codeKey := authorizationCodeKey(tenantID, codeHash)

	res, err := consumeAuthorizationCodeScript.Run(ctx, r.rdb, []string{usedKey, codeKey}).Result()
	if err != nil {
		if strings.Contains(err.Error(), "already_used") {
			return nil, domain.ErrAuthorizationCodeUsed
		}
		if err == goredis.Nil {
			return nil, domain.ErrAuthorizationCodeNotFound
		}
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	if res == nil {
		return nil, domain.ErrAuthorizationCodeNotFound
	}

	raw, err := scriptString(res)
	if err != nil {
		return nil, err
	}

	var c domain.AuthorizationCode
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("unmarshal authorization code: %w", err)
	}
	if c.IsExpired() {
		return nil, domain.ErrAuthorizationCodeExpired
	}
	return &c, nil
}

func scriptString(res any) (string, error) {
	switch v := res.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", fmt.Errorf("unexpected result type from consume script: %T", res)
	}
}
