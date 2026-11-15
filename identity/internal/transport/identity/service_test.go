package identity

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/granto-io/granto/identity/gen/identity/v1"
	"github.com/granto-io/granto/identity/internal/domain"
)

type fakeRepo struct {
	users map[string]*domain.User
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{users: make(map[string]*domain.User)}
}

func (r *fakeRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	if u, ok := r.users[email]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *fakeRepo) GetOrCreateByEmail(_ context.Context, email string) (*domain.User, error) {
	if u, ok := r.users[email]; ok {
		return u, nil
	}
	u := &domain.User{Email: email}
	r.users[email] = u
	return u, nil
}

func (r *fakeRepo) Create(_ context.Context, user *domain.User) error {
	if _, ok := r.users[user.Email]; ok {
		return domain.ErrEmailTaken
	}
	r.users[user.Email] = user
	return nil
}

func (r *fakeRepo) SetPassword(_ context.Context, id string, passwordHash string) error {
	for _, u := range r.users {
		if u.ID.String() == id {
			u.PasswordHash = passwordHash
			return nil
		}
	}
	return domain.ErrUserNotFound
}

func testService() *Service {
	return NewService(newFakeRepo(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestVerifyPassword_Success(t *testing.T) {
	t.Parallel()
	svc := testService()

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	svc.users.(*fakeRepo).users["user@example.com"] = &domain.User{Email: "user@example.com", PasswordHash: string(hash)}

	resp, err := svc.VerifyPassword(context.Background(), &identityv1.VerifyPasswordRequest{
		Email:    "user@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !resp.GetVerified() {
		t.Fatal("expected verified=true")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	t.Parallel()
	svc := testService()

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	svc.users.(*fakeRepo).users["user@example.com"] = &domain.User{Email: "user@example.com", PasswordHash: string(hash)}

	resp, err := svc.VerifyPassword(context.Background(), &identityv1.VerifyPasswordRequest{
		Email:    "user@example.com",
		Password: "wrong",
	})
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if resp.GetVerified() {
		t.Fatal("expected verified=false")
	}
}

func TestVerifyPassword_UnknownUser(t *testing.T) {
	t.Parallel()
	svc := testService()

	resp, err := svc.VerifyPassword(context.Background(), &identityv1.VerifyPasswordRequest{
		Email:    "nobody@example.com",
		Password: "whatever",
	})
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if resp.GetVerified() {
		t.Fatal("expected verified=false for unknown user")
	}
}

func TestGetOrCreateUserByEmail_Creates(t *testing.T) {
	t.Parallel()
	svc := testService()

	u, err := svc.GetOrCreateUserByEmail(context.Background(), &identityv1.GetOrCreateUserByEmailRequest{
		Email: "new@example.com",
	})
	if err != nil {
		t.Fatalf("GetOrCreateUserByEmail: %v", err)
	}
	if u.GetEmail() != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", u.GetEmail())
	}
}

func TestGetOrCreateUserByEmail_InvalidEmail(t *testing.T) {
	t.Parallel()
	svc := testService()

	_, err := svc.GetOrCreateUserByEmail(context.Background(), &identityv1.GetOrCreateUserByEmailRequest{
		Email: "not-an-email",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}
