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
)

// Key: {tenantID}:flow_verifier:{id}

// FlowVerifierRepository is the Redis implementation of repository.FlowVerifierRepository.
type FlowVerifierRepository struct {
	rdb *goredis.Client
}

// NewFlowVerifierRepository constructs a flow-verifier repository.
func NewFlowVerifierRepository(client *iredis.Client) *FlowVerifierRepository {
	return &FlowVerifierRepository{rdb: client.RDB()}
}

func flowVerifierKey(tenantID, id uuid.UUID) string {
	return tenantID.String() + ":flow_verifier:" + id.String()
}

func (r *FlowVerifierRepository) Create(ctx context.Context, v *domain.FlowVerifier) error {
	if v == nil {
		return fmt.Errorf("flow verifier is nil")
	}
	if !v.ValidKind() {
		return fmt.Errorf("invalid flow verifier kind %q", v.Kind)
	}
	if v.RedirectTo == "" {
		return fmt.Errorf("flow verifier redirect_to is empty")
	}
	if v.SessionID == uuid.Nil {
		return fmt.Errorf("flow verifier session_id is empty")
	}
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	ttl := time.Until(v.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("flow verifier already expired")
	}

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal flow verifier: %w", err)
	}
	if err := r.rdb.Set(ctx, flowVerifierKey(v.TenantID, v.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("store flow verifier: %w", err)
	}
	return nil
}

func (r *FlowVerifierRepository) Consume(ctx context.Context, tenantID, id uuid.UUID) (*domain.FlowVerifier, error) {
	key := flowVerifierKey(tenantID, id)
	data, err := r.rdb.GetDel(ctx, key).Bytes()
	if err == goredis.Nil {
		return nil, domain.ErrFlowVerifierNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume flow verifier: %w", err)
	}
	var v domain.FlowVerifier
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("unmarshal flow verifier: %w", err)
	}
	if v.IsExpired() {
		return nil, domain.ErrFlowVerifierExpired
	}
	return &v, nil
}
