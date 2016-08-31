package account

import (
	"golang.org/x/net/context"

	"github.com/go-kit/kit/endpoint"
	"github.com/solher/styx/sessions"
)

// Endpoints collects all of the endpoints that compose an account service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.
type Endpoints struct {
	CreateSessionEndpoint              endpoint.Endpoint
	FindSessionByTokenEndpoint         endpoint.Endpoint
	DeleteSessionByTokenEndpoint       endpoint.Endpoint
	DeleteSessionsByOwnerTokenEndpoint endpoint.Endpoint
}

type createSessionRequest struct {
	Session *sessions.Session
}

type createSessionResponse struct {
	Session *sessions.Session
	Err     error
}

// MakeCreateSessionEndpoint returns an endpoint that invokes CreateSession on the service.
func MakeCreateSessionEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createSessionRequest)
		session, err := s.CreateSession(ctx, req.Session)
		return createSessionResponse{Session: session, Err: err}, nil
	}
}

type findSessionByTokenRequest struct {
	Token string
}

type findSessionByTokenResponse struct {
	Session *sessions.Session
	Err     error
}

// MakeFindSessionByTokenEndpoint returns an endpoint that invokes FindSessionByToken on the service.
func MakeFindSessionByTokenEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(findSessionByTokenRequest)
		session, err := s.FindSessionByToken(ctx, req.Token)
		return findSessionByTokenResponse{Session: session, Err: err}, nil
	}
}

type deleteSessionByTokenRequest struct {
	Token string
}

type deleteSessionByTokenResponse struct {
	Session *sessions.Session
	Err     error
}

// MakeDeleteSessionByTokenEndpoint returns an endpoint that invokes DeleteSessionByToken on the service.
func MakeDeleteSessionByTokenEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteSessionByTokenRequest)
		session, err := s.DeleteSessionByToken(ctx, req.Token)
		return deleteSessionByTokenResponse{Session: session, Err: err}, nil
	}
}

type deleteSessionsByOwnerTokenRequest struct {
	OwnerToken string
}

type deleteSessionsByOwnerTokenResponse struct {
	Sessions []sessions.Session
	Err      error
}

// MakeDeleteSessionsByOwnerTokenEndpoint returns an endpoint that invokes DeleteSessionsByOwnerToken on the service.
func MakeDeleteSessionsByOwnerTokenEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteSessionsByOwnerTokenRequest)
		sessions, err := s.DeleteSessionsByOwnerToken(ctx, req.OwnerToken)
		return deleteSessionsByOwnerTokenResponse{Sessions: sessions, Err: err}, nil
	}
}
