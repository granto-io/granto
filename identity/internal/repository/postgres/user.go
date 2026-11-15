package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/granto-io/granto/identity/internal/domain"
	"github.com/granto-io/granto/identity/internal/postgres"
	"github.com/granto-io/granto/identity/internal/repository"
)

// userColumns lists every users column in scan / SELECT order (one per line).
const userColumns = `
	id,
	email,
	password_hash,
	created_at,
	updated_at`

// UserRepository is the PostgreSQL implementation of repository.UserRepository.
type UserRepository struct {
	db *postgres.DB
}

// NewUserRepository constructs a user repository using the shared DB handle.
func NewUserRepository(db *postgres.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `SELECT` + userColumns + `
		FROM users
		WHERE email = $1
		  AND deleted_at IS NULL`

	u, err := scanUser(r.db.Conn(ctx).QueryRow(ctx, q, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (r *UserRepository) GetOrCreateByEmail(ctx context.Context, email string) (*domain.User, error) {
	u, err := r.GetByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}

	created := &domain.User{Email: email}
	if err := r.Create(ctx, created); err != nil {
		// A concurrent request may have created the same email between our
		// GetByEmail and Create; retry the read once.
		if errors.Is(err, domain.ErrEmailTaken) {
			return r.GetByEmail(ctx, email)
		}
		return nil, err
	}
	return created, nil
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	const q = `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, created_at, updated_at`

	var passwordHash any
	if user.PasswordHash != "" {
		passwordHash = user.PasswordHash
	}
	err := r.db.Conn(ctx).QueryRow(ctx, q, user.Email, passwordHash).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if isUniqueViolation(err) {
		return domain.ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *UserRepository) SetPassword(ctx context.Context, id string, passwordHash string) error {
	const q = `
		UPDATE users
		SET password_hash = $2, updated_at = now()
		WHERE id = $1
		  AND deleted_at IS NULL`

	tag, err := r.db.Conn(ctx).Exec(ctx, q, id, passwordHash)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var _ repository.UserRepository = (*UserRepository)(nil)
