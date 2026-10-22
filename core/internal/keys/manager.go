package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
)

const useSig = "sig"

// Manager holds the active AS signing material (static or Postgres-backed).
type Manager struct {
	cfg    *config.Config
	repo   repository.SigningKeyRepository
	logger *slog.Logger

	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	kid        string
	algorithm  string
	static     bool
	// jwksCache is rebuilt only when signing material changes (load/rotate).
	jwksCache *JWKSet
}

// NewManager loads a static PEM key or ensures an auto-generated key in Postgres.
func NewManager(
	ctx context.Context,
	cfg *config.Config,
	repo repository.SigningKeyRepository,
	logger *slog.Logger,
) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Manager{
		cfg:       cfg,
		repo:      repo,
		logger:    logger,
		algorithm: cfg.Token.DefaultAlgorithm,
	}
	if m.algorithm == "" {
		m.algorithm = "RS256"
	}
	if m.algorithm != "RS256" {
		return nil, fmt.Errorf("unsupported signing algorithm %q", m.algorithm)
	}

	if cfg.Token.HasStaticSigningKey() {
		if err := m.loadStatic(); err != nil {
			return nil, err
		}
		m.logger.InfoContext(ctx, "signing key loaded from static source",
			"kid", m.kid,
			"algorithm", m.algorithm,
		)
		return m, nil
	}

	if err := m.ensureGenerated(ctx); err != nil {
		return nil, err
	}
	m.logger.InfoContext(ctx, "signing key ready (postgres)",
		"kid", m.kid,
		"algorithm", m.algorithm,
	)
	return m, nil
}

// Algorithm returns the active signing algorithm.
func (m *Manager) Algorithm() string {
	return m.algorithm
}

// SignJWT signs claims as a JWT with kid header.
func (m *Manager) SignJWT(claims jwt.MapClaims) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.privateKey == nil {
		return "", fmt.Errorf("signing key not loaded")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	return token.SignedString(m.privateKey)
}

// ParseJWT verifies an RS256 JWT with the active public key.
// Expiration and other registered claims are not enforced (callers may
// accept expired id_token_hint on logout).
func (m *Manager) ParseJWT(tokenString string) (jwt.MapClaims, error) {
	m.mu.RLock()
	priv := m.privateKey
	m.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("signing key not loaded")
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, err := parser.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return &priv.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// JWKS returns the public JWKS for the active key set.
// Results are cached in memory until signing keys are reloaded.
func (m *Manager) JWKS(ctx context.Context) (*JWKSet, error) {
	m.mu.RLock()
	if m.jwksCache != nil {
		out := cloneJWKSet(m.jwksCache)
		m.mu.RUnlock()
		return out, nil
	}
	static := m.static
	kid := m.kid
	alg := m.algorithm
	priv := m.privateKey
	m.mu.RUnlock()

	var set *JWKSet
	if static || m.repo == nil {
		if priv == nil {
			return nil, fmt.Errorf("signing key not loaded")
		}
		set = &JWKSet{Keys: []JWK{rsaPublicToJWK(&priv.PublicKey, kid, alg)}}
	} else {
		stored, err := m.repo.ListActiveKeys(ctx, domain.DefaultTenantID)
		if err != nil {
			return nil, err
		}
		if len(stored) == 0 {
			// Fallback to in-memory active key.
			set = &JWKSet{Keys: []JWK{rsaPublicToJWK(&priv.PublicKey, kid, alg)}}
		} else {
			out := make([]JWK, 0, len(stored))
			for _, k := range stored {
				jwk, err := publicPEMToJWK(k.PublicKey, k.KID, k.Algorithm)
				if err != nil {
					return nil, err
				}
				out = append(out, jwk)
			}
			set = &JWKSet{Keys: out}
		}
	}

	m.mu.Lock()
	if m.jwksCache == nil {
		m.jwksCache = set
	}
	out := cloneJWKSet(m.jwksCache)
	m.mu.Unlock()
	return out, nil
}

func cloneJWKSet(in *JWKSet) *JWKSet {
	if in == nil {
		return nil
	}
	keys := make([]JWK, len(in.Keys))
	copy(keys, in.Keys)
	return &JWKSet{Keys: keys}
}

func (m *Manager) loadStatic() error {
	pemBytes, err := readStaticPEM(m.cfg.Token.SigningKeys)
	if err != nil {
		return err
	}
	priv, err := parseRSAPrivateKeyPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("parse static private key: %w", err)
	}
	kid := strings.TrimSpace(m.cfg.Token.SigningKeys.KID)
	if kid == "" {
		kid = kidFromPublicKey(&priv.PublicKey)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.privateKey = priv
	m.kid = kid
	m.static = true
	m.jwksCache = nil
	return nil
}

func readStaticPEM(c config.SigningKeysConfig) ([]byte, error) {
	if file := strings.TrimSpace(c.PrivateKeyFile); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read signing key file: %w", err)
		}
		return b, nil
	}
	pemStr := strings.TrimSpace(c.PrivateKeyPEM)
	if pemStr == "" {
		return nil, fmt.Errorf("static signing key is empty")
	}
	// Allow env-style escaped newlines.
	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")
	return []byte(pemStr), nil
}

func (m *Manager) ensureGenerated(ctx context.Context) error {
	if m.repo == nil {
		return fmt.Errorf("signing key repository is required for auto-gen path")
	}
	enc, err := NewAESEncryptor(m.cfg.Token.MasterKey)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}

	existing, err := m.repo.GetActiveKey(ctx, domain.DefaultTenantID, m.algorithm)
	if err == nil {
		return m.loadFromRecord(existing, enc)
	}
	if !errors.Is(err, domain.ErrSigningKeyNotFound) {
		return err
	}

	if err := m.generateAndStore(ctx, enc); err != nil {
		return err
	}

	winner, err := m.repo.GetActiveKey(ctx, domain.DefaultTenantID, m.algorithm)
	if err != nil {
		return fmt.Errorf("verify signing key after create: %w", err)
	}
	return m.loadFromRecord(winner, enc)
}

func (m *Manager) generateAndStore(ctx context.Context, enc Encryptor) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	privPEM := encodeRSAPrivateKeyPEM(priv)
	pubPEM := encodeRSAPublicKeyPEM(&priv.PublicKey)
	encrypted, err := enc.Encrypt(privPEM)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	rec := &domain.SigningKey{
		ID:         uuid.New(),
		TenantID:   domain.DefaultTenantID,
		KID:        uuid.NewString(),
		Algorithm:  m.algorithm,
		Use:        useSig,
		PublicKey:  string(pubPEM),
		PrivateKey: base64.StdEncoding.EncodeToString(encrypted),
		IsActive:   true,
	}
	if err := m.repo.Create(ctx, rec); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadFromRecord(rec *domain.SigningKey, enc Encryptor) error {
	raw, err := base64.StdEncoding.DecodeString(rec.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private key ciphertext: %w", err)
	}
	plain, err := enc.Decrypt(raw)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}
	priv, err := parseRSAPrivateKeyPEM(plain)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.privateKey = priv
	m.kid = rec.KID
	m.algorithm = rec.Algorithm
	m.static = false
	m.jwksCache = nil
	return nil
}
