package account

import (
	"encoding/json"
	"net/http"

	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pressly/chi"
	"github.com/solher/styx/helpers"
	"github.com/solher/styx/sessions"
	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

// MakeHTTPHandler returns a handler that makes a set of endpoints available
// on predefined paths.
func MakeHTTPHandler(ctx context.Context, endpoints Endpoints, tracer stdopentracing.Tracer, logger log.Logger) http.Handler {
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(errorEncoder),
		httptransport.ServerErrorLogger(logger),
	}

	createSessionHandler := httptransport.NewServer(
		ctx,
		endpoints.CreateSessionEndpoint,
		DecodeHTTPCreateSessionRequest,
		EncodeHTTPCreateSessionResponse,
		append(options, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Create session", logger)))...,
	)
	findSessionByTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.FindSessionByTokenEndpoint,
		DecodeHTTPFindSessionByTokenRequest,
		EncodeHTTPFindSessionByTokenResponse,
		append(options, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Find session by token", logger)))...,
	)
	deleteSessionByTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.DeleteSessionByTokenEndpoint,
		DecodeHTTPDeleteSessionByTokenRequest,
		EncodeHTTPDeleteSessionByTokenResponse,
		append(options, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Delete session by token", logger)))...,
	)
	deleteSessionByOwnerTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.DeleteSessionsByOwnerTokenEndpoint,
		DecodeHTTPDeleteSessionsByOwnerTokenRequest,
		EncodeHTTPDeleteSessionsByOwnerTokenResponse,
		append(options, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Delete session by owner token", logger)))...,
	)

	r := chi.NewRouter()
	r.Route("/sessions", func(r chi.Router) {
		r.Post("/", createSessionHandler.ServeHTTP)
		r.Get("/:token", findSessionByTokenHandler.ServeHTTP)
		r.Delete("/:token", deleteSessionByTokenHandler.ServeHTTP)
		r.Delete("/", deleteSessionByOwnerTokenHandler.ServeHTTP)
	})

	return r
}

// DecodeHTTPCreateSessionRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPCreateSessionRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var session *sessions.Session
	if err := json.NewDecoder(r.Body).Decode(session); err != nil {
		return nil, err
	}
	return createSessionRequest{
		Session: session,
	}, nil
}

// EncodeHTTPCreateSessionResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPCreateSessionResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(createSessionResponse)
	if res.Err != nil {
		errorEncoder(ctx, res.Err, w)
	}
	return encodeSession(ctx, w, 201, res.Session)
}

// DecodeHTTPFindSessionByTokenRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPFindSessionByTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return findSessionByTokenRequest{
		Token: chi.URLParam(r, "token"),
	}, nil
}

// EncodeHTTPFindSessionByTokenResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPFindSessionByTokenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(findSessionByTokenResponse)
	if res.Err != nil {
		errorEncoder(ctx, res.Err, w)
	}
	return encodeSession(ctx, w, 200, res.Session)
}

// DecodeHTTPDeleteSessionByTokenRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPDeleteSessionByTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return deleteSessionByTokenRequest{
		Token: chi.URLParam(r, "token"),
	}, nil
}

// EncodeHTTPDeleteSessionByTokenResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPDeleteSessionByTokenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(deleteSessionByTokenResponse)
	if res.Err != nil {
		errorEncoder(ctx, res.Err, w)
	}
	return encodeSession(ctx, w, 200, res.Session)
}

// DecodeHTTPDeleteSessionsByOwnerTokenRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPDeleteSessionsByOwnerTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return deleteSessionsByOwnerTokenRequest{
		OwnerToken: r.URL.Query().Get("ownerToken"),
	}, nil
}

// EncodeHTTPDeleteSessionsByOwnerTokenResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPDeleteSessionsByOwnerTokenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(deleteSessionsByOwnerTokenResponse)
	if res.Err != nil {
		errorEncoder(ctx, res.Err, w)
	}
	return encodeSessions(ctx, w, 200, res.Sessions)
}

func errorEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	if e, ok := err.(httptransport.Error); ok && e.Domain == httptransport.DomainDecode {
		helpers.EncodeAPIError(ctx, helpers.ErrBodyDecoding, w)
		return
	}
	var apiError helpers.APIError
	switch err {
	case sessions.ErrNotFound:
		apiError = helpers.ErrForbidden
	default:
		apiError = helpers.ErrInternal
		helpers.TraceError(ctx, err)
	}
	helpers.EncodeAPIError(ctx, apiError, w)
}

func encodeSession(ctx context.Context, w http.ResponseWriter, status int, session *sessions.Session) error {
	helpers.EncodeHTTPHeaders(ctx, w, status)
	return json.NewEncoder(w).Encode(session)
}

func encodeSessions(ctx context.Context, w http.ResponseWriter, status int, sessions []sessions.Session) error {
	helpers.EncodeHTTPHeaders(ctx, w, status)
	return json.NewEncoder(w).Encode(sessions)
}
