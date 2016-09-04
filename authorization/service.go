package authorization

import (
	"context"

	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
	"github.com/solher/styx/sessions"
)

// Service represents the authorization service interface.
type Service interface {
	AuthorizeToken(ctx context.Context, hostname, path, token string) (*sessions.Session, error)
	GetRedirectURL(ctx context.Context, hostname string) (string, error)
}

type service struct {
	policyRepo   policies.Repository
	resourceRepo resources.Repository
}

// NewService returns a new instance of the authorization service.
func NewService(policyRepo policies.Repository, resourceRepo resources.Repository) Service {
	return &service{
		policyRepo:   policyRepo,
		resourceRepo: resourceRepo,
	}
}

// AuthorizeToken authorizes a given token to access a given URL.
func (s *service) AuthorizeToken(ctx context.Context, hostname, path, token string) (*sessions.Session, error) {
	return nil, nil
}

// GetRedirectURL returns the URL to which the user must be redirected in case of a denied
// access to the given hostname.
func (s *service) GetRedirectURL(ctx context.Context, hostname string) (string, error) {
	return "", nil
}
