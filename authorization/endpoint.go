package authorization

import (
	"golang.org/x/net/context"

	"github.com/go-kit/kit/endpoint"
	"github.com/solher/styx/sessions"
)

// Endpoints collects all of the endpoints that compose an authorization service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.
type Endpoints struct {
	AuthorizeTokenEndpoint endpoint.Endpoint
	RedirectURLEndpoint    endpoint.Endpoint
}

type authorizeTokenRequest struct {
	Hostname, Path, Token string
}

type authorizeTokenResponse struct {
	Session *sessions.Session
	Err     error
}

// MakeAuthorizeTokenEndpoint returns an endpoint that invokes AuthorizeToken on the service.
func MakeAuthorizeTokenEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(authorizeTokenRequest)
		session, err := s.AuthorizeToken(ctx, req.Hostname, req.Path, req.Token)
		return authorizeTokenResponse{
			Session: session,
			Err:     err,
		}, nil
	}
}

type redirectURLRequest struct {
	Hostname string
}

type redirectURLResponse struct {
	URL string
	Err error
}

// MakeRedirectURLEndpoint returns an endpoint that invokes RedirectURL on the service.
func MakeRedirectURLEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(redirectURLRequest)
		url, err := s.RedirectURL(ctx, req.Hostname)
		return redirectURLResponse{
			URL: url,
			Err: err,
		}, nil
	}
}
