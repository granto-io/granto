package identity

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/granto-io/granto/identity/gen/identity/v1"
	"github.com/granto-io/granto/identity/internal/domain"
	"github.com/granto-io/granto/identity/internal/repository"
)

// dummyPasswordHash is a real bcrypt hash used only to equalize timing when
// the user is unknown or has no password. Without this, a missing email
// returns in ~DB RTT while a real user burns tens of ms in bcrypt — enough
// to enumerate valid emails via VerifyPassword.
var (
	dummyPasswordHash     []byte
	dummyPasswordHashOnce sync.Once
)

func passwordDummyHash() []byte {
	dummyPasswordHashOnce.Do(func() {
		h, err := bcrypt.GenerateFromPassword([]byte("granto-dummy-password"), bcrypt.DefaultCost)
		if err != nil {
			panic("identity: generate dummy password hash: " + err.Error())
		}
		dummyPasswordHash = h
	})
	return dummyPasswordHash
}

// Service implements IdentityService.
type Service struct {
	identityv1.UnimplementedIdentityServiceServer

	users  repository.UserRepository
	logger *slog.Logger
}

// NewService constructs the identity service.
func NewService(users repository.UserRepository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{users: users, logger: logger}
}

func (s *Service) GetOrCreateUserByEmail(ctx context.Context, req *identityv1.GetOrCreateUserByEmailRequest) (*identityv1.User, error) {
	email, err := normalizeEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	u, err := s.users.GetOrCreateByEmail(ctx, email)
	if err != nil {
		s.logger.ErrorContext(ctx, "get or create user", "error", err)
		return nil, status.Error(codes.Internal, "could not resolve user")
	}
	return userToProto(u), nil
}

func (s *Service) GetUserByEmail(ctx context.Context, req *identityv1.GetUserByEmailRequest) (*identityv1.User, error) {
	email, err := normalizeEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	u, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "get user by email", "error", err)
		return nil, status.Error(codes.Internal, "could not load user")
	}
	return userToProto(u), nil
}

func (s *Service) CreateUser(ctx context.Context, req *identityv1.CreateUserRequest) (*identityv1.User, error) {
	email, err := normalizeEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}

	u := &domain.User{Email: email}
	if pwd := req.GetPassword(); pwd != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		if err != nil {
			s.logger.ErrorContext(ctx, "hash password", "error", err)
			return nil, status.Error(codes.Internal, "could not store password")
		}
		u.PasswordHash = string(hash)
	}

	if err := s.users.Create(ctx, u); err != nil {
		if errors.Is(err, domain.ErrEmailTaken) {
			return nil, status.Error(codes.AlreadyExists, "email already taken")
		}
		s.logger.ErrorContext(ctx, "create user", "error", err)
		return nil, status.Error(codes.Internal, "could not create user")
	}
	return userToProto(u), nil
}

func (s *Service) VerifyPassword(ctx context.Context, req *identityv1.VerifyPasswordRequest) (*identityv1.VerifyPasswordResponse, error) {
	email, err := normalizeEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}

	u, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, domain.ErrUserNotFound) {
		// Same work as a failed password check (timing side-channel).
		_ = bcrypt.CompareHashAndPassword(passwordDummyHash(), []byte(req.GetPassword()))
		return &identityv1.VerifyPasswordResponse{Verified: false}, nil
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "get user for verify", "error", err)
		return nil, status.Error(codes.Internal, "could not load user")
	}

	hash := []byte(u.PasswordHash)
	if len(hash) == 0 {
		hash = passwordDummyHash()
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(req.GetPassword())); err != nil {
		return &identityv1.VerifyPasswordResponse{Verified: false}, nil
	}
	return &identityv1.VerifyPasswordResponse{Verified: true, User: userToProto(u)}, nil
}

func userToProto(u *domain.User) *identityv1.User {
	return &identityv1.User{
		Id:          u.ID.String(),
		Email:       u.Email,
		HasPassword: u.HasPassword(),
	}
}

func normalizeEmail(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 {
		return "", errors.New("invalid email")
	}
	// Keep it simple: lowercase and require a single '@' with non-empty parts.
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || strings.IndexByte(s, '@') != at {
		return "", errors.New("invalid email")
	}
	return strings.ToLower(s), nil
}
