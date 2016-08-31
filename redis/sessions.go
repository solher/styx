package redis

import (
	"context"

	"github.com/solher/styx/sessions"
)

type sessionRepository struct {
}

// NewSessionRepository returns a new instance of a Redis backed session repository.
func NewSessionRepository() sessions.Repository {
	return &sessionRepository{}
}

// Create creates a new session and returns it.
func (r *sessionRepository) Create(ctx context.Context, session *sessions.Session) (*sessions.Session, error) {
	return nil, nil
}

// FindByToken finds a session by its token and returns it.
func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*sessions.Session, error) {
	return nil, nil
}

// DeleteByToken deletes a session by its token and returns it.
func (r *sessionRepository) DeleteByToken(ctx context.Context, token string) (*sessions.Session, error) {
	return nil, nil
}

// DeleteByOwnerToken deletes all the sessions marked with the given owner token.
// Useful to implement delete cascades on user deletions.
func (r *sessionRepository) DeleteByOwnerToken(ctx context.Context, ownerToken string) ([]sessions.Session, error) {
	return nil, nil
}
