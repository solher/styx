package account

import (
	"context"

	"github.com/solher/styx/sessions"
)

// Service represents the account service interface.
type Service interface {
	CreateSession(ctx context.Context, session *sessions.Session) (*sessions.Session, error)
	FindSessionByToken(ctx context.Context, token string) (*sessions.Session, error)
	DeleteSessionByToken(ctx context.Context, token string) (*sessions.Session, error)
	DeleteSessionsByOwnerToken(ctx context.Context, ownerToken string) ([]sessions.Session, error)
}

type service struct {
	sessionRepo sessions.Repository
}

// NewService returns a new instance of the account service.
func NewService(sessionRepo sessions.Repository) Service {
	return &service{
		sessionRepo: sessionRepo,
	}
}

func (s *service) CreateSession(ctx context.Context, session *sessions.Session) (*sessions.Session, error) {
	return s.sessionRepo.Create(ctx, session)
}

func (s *service) FindSessionByToken(ctx context.Context, token string) (*sessions.Session, error) {
	return s.sessionRepo.FindByToken(ctx, token)
}

func (s *service) DeleteSessionByToken(ctx context.Context, token string) (*sessions.Session, error) {
	return s.sessionRepo.DeleteByToken(ctx, token)
}

func (s *service) DeleteSessionsByOwnerToken(ctx context.Context, ownerToken string) ([]sessions.Session, error) {
	return s.sessionRepo.DeleteByOwnerToken(ctx, ownerToken)
}
