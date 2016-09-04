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
	RedirectEndpoint       endpoint.Endpoint
}

type authorizeTokenRequest struct {
	Hostname, Path, Token string
}

type authorizeTokenResponse struct {
	Token   string
	Session *sessions.Session
	Err     error
}

// MakeAuthorizeTokenEndpoint returns an endpoint that invokes AuthorizeToken on the service.
func MakeAuthorizeTokenEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(authorizeTokenRequest)
		session, err := s.AuthorizeToken(ctx, req.Hostname, req.Path, req.Token)
		return authorizeTokenResponse{
			Token:   req.Token,
			Session: session,
			Err:     err,
		}, nil
	}
}

type redirectRequest struct {
	RequestURL, Hostname string
}

type redirectResponse struct {
	RequestURL, RedirectURL string
	Err                     error
}

// MakeRedirectEndpoint returns an endpoint that invokes Redirect on the service.
func MakeRedirectEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(redirectRequest)
		url, err := s.Redirect(ctx, req.Hostname)
		return redirectResponse{
			RequestURL:  req.RequestURL,
			RedirectURL: url,
			Err:         err,
		}, nil
	}
}
