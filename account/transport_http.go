package account

import (
	"encoding/json"
	"net/http"

	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
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
	opts := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(helpers.TransportErrorEncoder),
		httptransport.ServerErrorLogger(logger),
	}
	createSessionHandler := httptransport.NewServer(
		ctx,
		endpoints.CreateSessionEndpoint,
		DecodeHTTPCreateSessionRequest,
		EncodeHTTPCreateSessionResponse,
		append(opts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Create session", logger)))...,
	)
	findSessionByTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.FindSessionByTokenEndpoint,
		DecodeHTTPFindSessionByTokenRequest,
		EncodeHTTPFindSessionByTokenResponse,
		append(opts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Find session by token", logger)))...,
	)
	deleteSessionByTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.DeleteSessionByTokenEndpoint,
		DecodeHTTPDeleteSessionByTokenRequest,
		EncodeHTTPDeleteSessionByTokenResponse,
		append(opts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Delete session by token", logger)))...,
	)
	deleteSessionByOwnerTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.DeleteSessionsByOwnerTokenEndpoint,
		DecodeHTTPDeleteSessionsByOwnerTokenRequest,
		EncodeHTTPDeleteSessionsByOwnerTokenResponse,
		append(opts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Delete session by owner token", logger)))...,
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
	session := &sessions.Session{}
	if err := json.NewDecoder(r.Body).Decode(session); err != nil {
		return nil, helpers.WithErrBodyDecoding(errors.Wrap(err, "could not decode the session"))
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
		return businessErrorEncoder(ctx, res.Err, w)
	}
	defer helpers.TraceStatusAndFinish(ctx, w.Header(), 201)
	encodeSession(w, res.Session, 201)
	return nil
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
		return businessErrorEncoder(ctx, res.Err, w)
	}
	defer helpers.TraceStatusAndFinish(ctx, w.Header(), 200)
	encodeSession(w, res.Session, 200)
	return nil
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
		return businessErrorEncoder(ctx, res.Err, w)
	}
	defer helpers.TraceStatusAndFinish(ctx, w.Header(), 200)
	encodeSession(w, res.Session, 200)
	return nil
}

// DecodeHTTPDeleteSessionsByOwnerTokenRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPDeleteSessionsByOwnerTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	values, ok := r.URL.Query()["ownerToken"]
	if !ok {
		return nil, helpers.WithErrQueryParam(errors.New("ownerToken parameter is required"), "ownerToken")
	}
	return deleteSessionsByOwnerTokenRequest{
		OwnerToken: values[0],
	}, nil
}

// EncodeHTTPDeleteSessionsByOwnerTokenResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPDeleteSessionsByOwnerTokenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(deleteSessionsByOwnerTokenResponse)
	if res.Err != nil {
		return businessErrorEncoder(ctx, res.Err, w)
	}
	defer helpers.TraceStatusAndFinish(ctx, w.Header(), 200)
	encodeSessions(w, res.Sessions, 200)
	return nil
}

func businessErrorEncoder(ctx context.Context, err error, w http.ResponseWriter) error {
	var apiError helpers.APIError
	if field, reason, ok := isErrValidation(err); ok {
		apiError = helpers.APIValidation
		apiError.Params["field"] = field
		apiError.Params["reason"] = reason
	} else if isErrNotFound(err) {
		apiError = helpers.APIForbidden
	} else {
		return err
	}

	defer helpers.TraceAPIErrorAndFinish(ctx, w.Header(), apiError)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiError.Status)
	json.NewEncoder(w).Encode(apiError)
	return nil
}

func encodeSession(w http.ResponseWriter, session *sessions.Session, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(session)
}

func encodeSessions(w http.ResponseWriter, sessions []sessions.Session, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(sessions)
}
