package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/postgres"
	"github.com/granto-io/granto/core/internal/repository"
)

// clientColumns lists every clients column in scan / SELECT order (one per line).
const clientColumns = `
	id,
	tenant_id,
	client_id,
	client_secret_hash,
	name,
	description,
	client_type,
	grant_types,
	response_types,
	redirect_uris,
	allowed_cors_origins,
	allowed_scopes,
	default_scopes,
	audience,
	token_endpoint_auth_method,
	token_endpoint_auth_signing_alg,
	require_pkce,
	subject_type,
	sector_identifier_uri,
	id_token_signed_alg,
	userinfo_signed_alg,
	post_logout_uris,
	frontchannel_logout_uri,
	frontchannel_logout_session_required,
	backchannel_logout_uri,
	backchannel_logout_session_required,
	access_token_ttl,
	refresh_token_ttl,
	id_token_ttl,
	skip_consent,
	logo_uri,
	client_uri,
	policy_uri,
	tos_uri,
	contacts,
	metadata,
	protocols,
	jwks,
	jwks_uri,
	registration_access_token_hash,
	is_dynamic,
	created_at,
	updated_at,
	deleted_at`

// ClientRepository is the PostgreSQL implementation of repository.ClientRepository.
type ClientRepository struct {
	db *postgres.DB
}

// NewClientRepository constructs a client repository using the shared DB handle.
func NewClientRepository(db *postgres.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*domain.Client, error) {
	const q = `SELECT` + clientColumns + `
		FROM clients
		WHERE tenant_id = $1
		  AND client_id = $2
		  AND deleted_at IS NULL`
	c, err := scanClient(r.db.Conn(ctx).QueryRow(ctx, q, tenantID, clientID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrClientNotFound
	}
	return c, err
}

func (r *ClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	const q = `SELECT` + clientColumns + `
		FROM clients
		WHERE id = $1
		  AND deleted_at IS NULL`
	c, err := scanClient(r.db.Conn(ctx).QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrClientNotFound
	}
	return c, err
}

func (r *ClientRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.ClientFilter) ([]*domain.Client, error) {
	q := `SELECT` + clientColumns + `
		FROM clients
		WHERE tenant_id = $1
		  AND deleted_at IS NULL`
	args := []any{tenantID}

	if filter.Search != "" {
		args = append(args, "%"+filter.Search+"%")
		idx := len(args)
		q += fmt.Sprintf(" AND (name ILIKE $%d OR client_id ILIKE $%d)", idx, idx)
	}
	q += " ORDER BY created_at DESC"
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := r.db.Conn(ctx).Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (r *ClientRepository) Create(ctx context.Context, c *domain.Client) error {
	const q = `
		INSERT INTO clients (
			id,
			tenant_id,
			client_id,
			client_secret_hash,
			name,
			description,
			client_type,
			grant_types,
			response_types,
			redirect_uris,
			allowed_cors_origins,
			allowed_scopes,
			default_scopes,
			audience,
			token_endpoint_auth_method,
			token_endpoint_auth_signing_alg,
			require_pkce,
			subject_type,
			sector_identifier_uri,
			id_token_signed_alg,
			userinfo_signed_alg,
			post_logout_uris,
			frontchannel_logout_uri,
			frontchannel_logout_session_required,
			backchannel_logout_uri,
			backchannel_logout_session_required,
			access_token_ttl,
			refresh_token_ttl,
			id_token_ttl,
			skip_consent,
			logo_uri,
			client_uri,
			policy_uri,
			tos_uri,
			contacts,
			metadata,
			protocols,
			jwks,
			jwks_uri,
			registration_access_token_hash,
			is_dynamic
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10,
			$11,
			$12,
			$13,
			$14,
			$15,
			$16,
			$17,
			$18,
			$19,
			$20,
			$21,
			$22,
			$23,
			$24,
			$25,
			$26,
			$27,
			$28,
			$29,
			$30,
			$31,
			$32,
			$33,
			$34,
			$35,
			$36,
			$37,
			$38,
			$39,
			$40,
			$41
		)`

	meta, err := marshalJSONMap(c.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	jwks, err := marshalJSONMapNullable(c.JWKS)
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}

	authMethod := c.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = domain.TokenEndpointAuthClientSecretBasic
	}
	subjectType := c.SubjectType
	if subjectType == "" {
		subjectType = domain.SubjectTypePublic
	}
	idAlg := c.IDTokenSignedAlg
	if idAlg == "" {
		idAlg = "RS256"
	}
	uiAlg := c.UserinfoSignedAlg
	if uiAlg == "" {
		uiAlg = "none"
	}
	protocols := c.Protocols
	if protocols == nil {
		protocols = []string{"oauth2", "oidc"}
	}

	_, err = r.db.Conn(ctx).Exec(
		ctx,
		q,
		c.ID,
		c.TenantID,
		c.ClientID,
		nullableStr(c.ClientSecretHash),
		c.Name,
		nullableStr(c.Description),
		string(c.ClientType),
		domain.GrantTypesToStrings(c.GrantTypes),
		c.ResponseTypes,
		c.RedirectURIs,
		c.AllowedCORSOrigins,
		c.AllowedScopes,
		c.DefaultScopes,
		c.Audience,
		string(authMethod),
		nullableStr(c.TokenEndpointAuthSigningAlg),
		c.RequirePKCE,
		string(subjectType),
		nullableStr(c.SectorIdentifierURI),
		idAlg,
		uiAlg,
		c.PostLogoutURIs,
		nullableStr(c.FrontChannelLogoutURI),
		c.FrontChannelLogoutSessionRequired,
		nullableStr(c.BackChannelLogoutURI),
		c.BackChannelLogoutSessionRequired,
		durationToInterval(c.AccessTokenTTL),
		durationToInterval(c.RefreshTokenTTL),
		durationToInterval(c.IDTokenTTL),
		c.SkipConsent,
		nullableStr(c.LogoURI),
		nullableStr(c.ClientURI),
		nullableStr(c.PolicyURI),
		nullableStr(c.TosURI),
		c.Contacts,
		meta,
		protocols,
		jwks,
		nullableStr(c.JWKSURI),
		nullableStr(c.RegistrationAccessTokenHash),
		c.IsDynamic,
	)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	return nil
}

func (r *ClientRepository) Update(ctx context.Context, c *domain.Client) error {
	const q = `
		UPDATE clients SET
			client_secret_hash = $1,
			name = $2,
			description = $3,
			client_type = $4,
			grant_types = $5,
			response_types = $6,
			redirect_uris = $7,
			allowed_cors_origins = $8,
			allowed_scopes = $9,
			default_scopes = $10,
			audience = $11,
			token_endpoint_auth_method = $12,
			token_endpoint_auth_signing_alg = $13,
			require_pkce = $14,
			subject_type = $15,
			sector_identifier_uri = $16,
			id_token_signed_alg = $17,
			userinfo_signed_alg = $18,
			post_logout_uris = $19,
			frontchannel_logout_uri = $20,
			frontchannel_logout_session_required = $21,
			backchannel_logout_uri = $22,
			backchannel_logout_session_required = $23,
			access_token_ttl = $24,
			refresh_token_ttl = $25,
			id_token_ttl = $26,
			skip_consent = $27,
			logo_uri = $28,
			client_uri = $29,
			policy_uri = $30,
			tos_uri = $31,
			contacts = $32,
			metadata = $33,
			protocols = $34,
			jwks = $35,
			jwks_uri = $36,
			registration_access_token_hash = $37,
			is_dynamic = $38,
			updated_at = now()
		WHERE id = $39
		  AND deleted_at IS NULL`

	meta, err := marshalJSONMap(c.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	jwks, err := marshalJSONMapNullable(c.JWKS)
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}

	tag, err := r.db.Conn(ctx).Exec(
		ctx,
		q,
		nullableStr(c.ClientSecretHash),
		c.Name,
		nullableStr(c.Description),
		string(c.ClientType),
		domain.GrantTypesToStrings(c.GrantTypes),
		c.ResponseTypes,
		c.RedirectURIs,
		c.AllowedCORSOrigins,
		c.AllowedScopes,
		c.DefaultScopes,
		c.Audience,
		string(c.TokenEndpointAuthMethod),
		nullableStr(c.TokenEndpointAuthSigningAlg),
		c.RequirePKCE,
		string(c.SubjectType),
		nullableStr(c.SectorIdentifierURI),
		c.IDTokenSignedAlg,
		c.UserinfoSignedAlg,
		c.PostLogoutURIs,
		nullableStr(c.FrontChannelLogoutURI),
		c.FrontChannelLogoutSessionRequired,
		nullableStr(c.BackChannelLogoutURI),
		c.BackChannelLogoutSessionRequired,
		durationToInterval(c.AccessTokenTTL),
		durationToInterval(c.RefreshTokenTTL),
		durationToInterval(c.IDTokenTTL),
		c.SkipConsent,
		nullableStr(c.LogoURI),
		nullableStr(c.ClientURI),
		nullableStr(c.PolicyURI),
		nullableStr(c.TosURI),
		c.Contacts,
		meta,
		c.Protocols,
		jwks,
		nullableStr(c.JWKSURI),
		nullableStr(c.RegistrationAccessTokenHash),
		c.IsDynamic,
		c.ID,
	)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrClientNotFound
	}
	return nil
}

func (r *ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE clients
		SET deleted_at = now(),
		    updated_at = now()
		WHERE id = $1
		  AND deleted_at IS NULL`
	tag, err := r.db.Conn(ctx).Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrClientNotFound
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanClient(row scanner) (*domain.Client, error) {
	var (
		id, tenantID                  uuid.UUID
		clientID, name                string
		secretHash, desc              pgtype.Text
		clientType                    string
		grantTypes, responseTypes     []string
		redirectURIs, corsOrigins     []string
		allowedScopes, defaultScopes  []string
		audience                      []string
		authMethod                    string
		authSigningAlg                pgtype.Text
		requirePKCE                   bool
		subjectType                   string
		sectorURI                     pgtype.Text
		idTokenAlg, uiAlg             string
		postLogoutURIs                []string
		fcLogoutURI, bcLogoutURI      pgtype.Text
		fcLogoutSession, bcLogoutSess bool
		accessTTL, refreshTTL, idTTL  pgtype.Interval
		skipConsent                   bool
		logoURI, clientURI            pgtype.Text
		policyURI, tosURI             pgtype.Text
		contacts                      []string
		metaRaw                       []byte
		protocols                     []string
		jwksRaw                       []byte
		jwksURI                       pgtype.Text
		regAccessTokenHash            pgtype.Text
		isDynamic                     bool
		createdAt, updatedAt          time.Time
		deletedAt                     *time.Time
	)

	err := row.Scan(
		&id,
		&tenantID,
		&clientID,
		&secretHash,
		&name,
		&desc,
		&clientType,
		&grantTypes,
		&responseTypes,
		&redirectURIs,
		&corsOrigins,
		&allowedScopes,
		&defaultScopes,
		&audience,
		&authMethod,
		&authSigningAlg,
		&requirePKCE,
		&subjectType,
		&sectorURI,
		&idTokenAlg,
		&uiAlg,
		&postLogoutURIs,
		&fcLogoutURI,
		&fcLogoutSession,
		&bcLogoutURI,
		&bcLogoutSess,
		&accessTTL,
		&refreshTTL,
		&idTTL,
		&skipConsent,
		&logoURI,
		&clientURI,
		&policyURI,
		&tosURI,
		&contacts,
		&metaRaw,
		&protocols,
		&jwksRaw,
		&jwksURI,
		&regAccessTokenHash,
		&isDynamic,
		&createdAt,
		&updatedAt,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	meta, err := unmarshalJSONMap(metaRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	jwks, err := unmarshalJSONMap(jwksRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal jwks: %w", err)
	}

	return &domain.Client{
		ID:                                id,
		TenantID:                          tenantID,
		ClientID:                          clientID,
		ClientSecretHash:                  secretHash.String,
		Name:                              name,
		Description:                       desc.String,
		ClientType:                        domain.ClientType(clientType),
		GrantTypes:                        domain.GrantTypesFromStrings(grantTypes),
		ResponseTypes:                     responseTypes,
		RedirectURIs:                      redirectURIs,
		AllowedCORSOrigins:                corsOrigins,
		AllowedScopes:                     allowedScopes,
		DefaultScopes:                     defaultScopes,
		Audience:                          audience,
		TokenEndpointAuthMethod:           domain.TokenEndpointAuthMethod(authMethod),
		TokenEndpointAuthSigningAlg:       authSigningAlg.String,
		RequirePKCE:                       requirePKCE,
		SubjectType:                       domain.SubjectType(subjectType),
		SectorIdentifierURI:               sectorURI.String,
		IDTokenSignedAlg:                  idTokenAlg,
		UserinfoSignedAlg:                 uiAlg,
		PostLogoutURIs:                    postLogoutURIs,
		FrontChannelLogoutURI:             fcLogoutURI.String,
		FrontChannelLogoutSessionRequired: fcLogoutSession,
		BackChannelLogoutURI:              bcLogoutURI.String,
		BackChannelLogoutSessionRequired:  bcLogoutSess,
		AccessTokenTTL:                    intervalToDuration(accessTTL),
		RefreshTokenTTL:                   intervalToDuration(refreshTTL),
		IDTokenTTL:                        intervalToDuration(idTTL),
		SkipConsent:                       skipConsent,
		LogoURI:                           logoURI.String,
		ClientURI:                         clientURI.String,
		PolicyURI:                         policyURI.String,
		TosURI:                            tosURI.String,
		Contacts:                          contacts,
		Metadata:                          meta,
		Protocols:                         protocols,
		JWKS:                              jwks,
		JWKSURI:                           jwksURI.String,
		RegistrationAccessTokenHash:       regAccessTokenHash.String,
		IsDynamic:                         isDynamic,
		CreatedAt:                         createdAt,
		UpdatedAt:                         updatedAt,
		DeletedAt:                         deletedAt,
	}, nil
}
