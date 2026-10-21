package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/granto-io/granto/core/internal/domain"
	iredis "github.com/granto-io/granto/core/internal/redis"
)

// Keys:
//
//	{tenant}:access_token:{hash}
//	{tenant}:access_token_jti:{jti} → "{hash}:{expiresUnix}"
//	{tenant}:refresh_token:{hash}
//	{tenant}:session_refresh:{sessionID} → SET of refresh token hashes

// TokenRepository is the Redis implementation of repository.TokenRepository.
type TokenRepository struct {
	rdb *goredis.Client
}

// NewTokenRepository constructs a token repository.
func NewTokenRepository(client *iredis.Client) *TokenRepository {
	return &TokenRepository{rdb: client.RDB()}
}

func accessTokenKey(tenantID uuid.UUID, tokenHash string) string {
	return tenantID.String() + ":access_token:" + tokenHash
}

func accessTokenJTIKey(tenantID uuid.UUID, jti string) string {
	return tenantID.String() + ":access_token_jti:" + jti
}

func refreshTokenKey(tenantID uuid.UUID, tokenHash string) string {
	return tenantID.String() + ":refresh_token:" + tokenHash
}

func sessionRefreshKey(tenantID, sessionID uuid.UUID) string {
	return tenantID.String() + ":session_refresh:" + sessionID.String()
}

func (r *TokenRepository) CreateAccessToken(ctx context.Context, t *domain.AccessToken) error {
	if t == nil {
		return fmt.Errorf("access token is nil")
	}
	if err := validateAccessToken(t); err != nil {
		return err
	}
	if t.IssuedAt.IsZero() {
		t.IssuedAt = time.Now().UTC()
	}
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	if t.Audience == nil {
		t.Audience = []string{}
	}
	ttl := time.Until(t.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("access token already expired")
	}

	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal access token: %w", err)
	}
	jtiVal := t.TokenHash + ":" + strconv.FormatInt(t.ExpiresAt.Unix(), 10)

	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, accessTokenKey(t.TenantID, t.TokenHash), data, ttl)
	pipe.Set(ctx, accessTokenJTIKey(t.TenantID, t.JTI), jtiVal, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store access token: %w", err)
	}
	return nil
}

func (r *TokenRepository) GetAccessToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*domain.AccessToken, error) {
	data, err := r.rdb.Get(ctx, accessTokenKey(tenantID, tokenHash)).Bytes()
	if err == goredis.Nil {
		return nil, domain.ErrAccessTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}
	var t domain.AccessToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal access token: %w", err)
	}
	if t.IsExpired() {
		return &t, domain.ErrAccessTokenExpired
	}
	return &t, nil
}

func (r *TokenRepository) RevokeAccessToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) error {
	key := accessTokenKey(tenantID, tokenHash)
	data, err := r.rdb.Get(ctx, key).Bytes()
	if err == goredis.Nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get access token for revoke: %w", err)
	}
	var t domain.AccessToken
	_ = json.Unmarshal(data, &t)

	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, key)
	if t.JTI != "" {
		pipe.Del(ctx, accessTokenJTIKey(tenantID, t.JTI))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}
	return nil
}

func (r *TokenRepository) RevokeAccessTokenByJTI(ctx context.Context, tenantID uuid.UUID, jti string) error {
	jtiVal, err := r.rdb.Get(ctx, accessTokenJTIKey(tenantID, jti)).Result()
	if err == goredis.Nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup access token jti: %w", err)
	}
	parts := strings.SplitN(jtiVal, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, accessTokenKey(tenantID, parts[0]))
	pipe.Del(ctx, accessTokenJTIKey(tenantID, jti))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}
	return nil
}

func (r *TokenRepository) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	if t == nil {
		return fmt.Errorf("refresh token is nil")
	}
	if err := validateRefreshToken(t); err != nil {
		return err
	}
	if t.IssuedAt.IsZero() {
		t.IssuedAt = time.Now().UTC()
	}
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	if t.Audience == nil {
		t.Audience = []string{}
	}
	ttl := time.Until(t.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}

	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, refreshTokenKey(t.TenantID, t.TokenHash), data, ttl)
	if t.SessionID != uuid.Nil {
		sk := sessionRefreshKey(t.TenantID, t.SessionID)
		pipe.SAdd(ctx, sk, t.TokenHash)
		pipe.Expire(ctx, sk, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func (r *TokenRepository) GetRefreshToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*domain.RefreshToken, error) {
	data, err := r.rdb.Get(ctx, refreshTokenKey(tenantID, tokenHash)).Bytes()
	if err == goredis.Nil {
		return nil, domain.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	var t domain.RefreshToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}
	if t.IsExpired() {
		return &t, domain.ErrRefreshTokenExpired
	}
	return &t, nil
}

func (r *TokenRepository) RotateRefreshToken(ctx context.Context, tenantID uuid.UUID, oldHash string, next *domain.RefreshToken) error {
	if next == nil {
		return fmt.Errorf("next refresh token is nil")
	}
	if next.TenantID != tenantID {
		return fmt.Errorf("refresh token tenant mismatch")
	}
	if err := validateRefreshToken(next); err != nil {
		return err
	}
	if next.IssuedAt.IsZero() {
		next.IssuedAt = time.Now().UTC()
	}
	if next.Scopes == nil {
		next.Scopes = []string{}
	}
	if next.Audience == nil {
		next.Audience = []string{}
	}
	ttl := time.Until(next.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("next refresh token already expired")
	}

	old, err := r.GetRefreshToken(ctx, tenantID, oldHash)
	if err != nil {
		return err
	}

	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}

	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, refreshTokenKey(tenantID, oldHash))
	if old.SessionID != uuid.Nil {
		pipe.SRem(ctx, sessionRefreshKey(tenantID, old.SessionID), oldHash)
	}
	pipe.Set(ctx, refreshTokenKey(tenantID, next.TokenHash), data, ttl)
	if next.SessionID != uuid.Nil {
		sk := sessionRefreshKey(tenantID, next.SessionID)
		pipe.SAdd(ctx, sk, next.TokenHash)
		pipe.Expire(ctx, sk, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("rotate refresh token: %w", err)
	}
	return nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) error {
	key := refreshTokenKey(tenantID, tokenHash)
	data, err := r.rdb.Get(ctx, key).Bytes()
	if err == goredis.Nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get refresh token for revoke: %w", err)
	}
	var t domain.RefreshToken
	_ = json.Unmarshal(data, &t)

	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, key)
	if t.SessionID != uuid.Nil {
		pipe.SRem(ctx, sessionRefreshKey(tenantID, t.SessionID), tokenHash)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func (r *TokenRepository) RevokeRefreshTokensBySession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	sk := sessionRefreshKey(tenantID, sessionID)
	hashes, err := r.rdb.SMembers(ctx, sk).Result()
	if err != nil {
		return fmt.Errorf("list session refresh tokens: %w", err)
	}
	if len(hashes) == 0 {
		return nil
	}
	pipe := r.rdb.Pipeline()
	for _, h := range hashes {
		pipe.Del(ctx, refreshTokenKey(tenantID, h))
	}
	pipe.Del(ctx, sk)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke session refresh tokens: %w", err)
	}
	return nil
}

func validateAccessToken(t *domain.AccessToken) error {
	if t.TokenHash == "" || t.JTI == "" {
		return fmt.Errorf("access token hash or jti is empty")
	}
	if t.ClientID == "" || t.Subject == "" {
		return fmt.Errorf("access token missing client_id or subject")
	}
	return nil
}

func validateRefreshToken(t *domain.RefreshToken) error {
	if t.TokenHash == "" || t.JTI == "" {
		return fmt.Errorf("refresh token hash or jti is empty")
	}
	if t.ClientID == "" || t.Subject == "" {
		return fmt.Errorf("refresh token missing client_id or subject")
	}
	return nil
}
