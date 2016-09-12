package authorization

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pressly/chi"
	"github.com/solher/styx/helpers"
	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

// MakeHTTPHandler returns a handler that makes a set of endpoints available
// on predefined paths.
func MakeHTTPHandler(ctx context.Context, endpoints Endpoints, tracer stdopentracing.Tracer, logger log.Logger, opts ...HTTPHandlerOption) http.Handler {
	transportOpts := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(helpers.TransportErrorEncoder),
		httptransport.ServerErrorLogger(logger),
	}
	handlerOpts := &httpHandlerOptions{
		accessTokenCookie:     "access_token",
		accessTokenHeader:     "Styx-Access-Token",
		payloadHeader:         "Styx-Payload",
		sessionHeader:         "Styx-Session",
		redirectURLHeader:     "Redirect-Url",
		redirectURLQueryParam: "redirectUrl",
		requestURLHeader:      "Request-Url",
	}
	for _, opt := range opts {
		opt(handlerOpts)
	}
	authorizeTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.AuthorizeTokenEndpoint,
		DecodeHTTPAuthorizeTokenRequest(handlerOpts.accessTokenCookie, handlerOpts.accessTokenHeader, handlerOpts.requestURLHeader),
		EncodeHTTPAuthorizeTokenResponse(handlerOpts.accessTokenHeader, handlerOpts.payloadHeader, handlerOpts.sessionHeader),
		append(
			transportOpts,
			httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Authorize token", logger)),
			httptransport.ServerAfter(helpers.ToHTTPResponse(tracer, logger)),
		)...,
	)
	redirectHandler := httptransport.NewServer(
		ctx,
		endpoints.RedirectEndpoint,
		DecodeHTTPRedirectRequest(handlerOpts.requestURLHeader),
		EncodeHTTPRedirectResponse(handlerOpts.redirectURLHeader, handlerOpts.redirectURLQueryParam),
		append(transportOpts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Redirect URL", logger)))...,
	)

	r := chi.NewRouter()
	r.Get("/authorizeToken", authorizeTokenHandler.ServeHTTP)
	r.Get("/redirect", redirectHandler.ServeHTTP)

	return r
}

type httpHandlerOptions struct {
	accessTokenCookie     string
	accessTokenHeader     string
	payloadHeader         string
	sessionHeader         string
	redirectURLHeader     string
	redirectURLQueryParam string
	requestURLHeader      string
}

// HTTPHandlerOption sets an optional parameter for the HTTP handler.
type HTTPHandlerOption func(*httpHandlerOptions)

// AccessTokenCookie sets the cookie key to get the access token from.
func AccessTokenCookie(key string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.accessTokenCookie = key
	}
}

// AccessTokenHeader sets the header to get the access token from.
func AccessTokenHeader(header string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.accessTokenHeader = header
	}
}

// PayloadHeader sets the header where the session payload is set if
// access is granted.
func PayloadHeader(header string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.payloadHeader = header
	}
}

// SessionHeader sets the header where the session is set if
// access is granted.
func SessionHeader(header string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.sessionHeader = header
	}
}

// RedirectURLHeader sets the header where the redirect URL (the original
// user request URL) is set.
func RedirectURLHeader(header string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.redirectURLHeader = header
	}
}

// RedirectURLQueryParam sets the query parameter key where the
// redirect URL (the original user request URL) is set.
func RedirectURLQueryParam(key string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.redirectURLQueryParam = key
	}
}

// RequestURLHeader sets the header to get the URL requested by the user.
func RequestURLHeader(header string) HTTPHandlerOption {
	return func(o *httpHandlerOptions) {
		o.requestURLHeader = header
	}
}

// DecodeHTTPAuthorizeTokenRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPAuthorizeTokenRequest(accessTokenCookie, accessTokenHeader, requestURLHeader string) httptransport.DecodeRequestFunc {
	return func(_ context.Context, r *http.Request) (interface{}, error) {
		token := ""
		if cookie, err := r.Cookie(accessTokenCookie); err == nil {
			token = cookie.Value
		}
		if header := r.Header.Get(accessTokenHeader); header != "" {
			token = header
		}

		hostname, path := "", ""
		requestURL := r.Header.Get(requestURLHeader)
		if u, err := url.ParseRequestURI(requestURL); err == nil {
			hostname = u.Host
			path = u.Path
		}

		return authorizeTokenRequest{
			Hostname: hostname,
			Path:     path,
			Token:    token,
		}, nil
	}
}

// EncodeHTTPAuthorizeTokenResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPAuthorizeTokenResponse(accessTokenHeader, payloadHeader, sessionHeader string) httptransport.EncodeResponseFunc {
	return func(ctx context.Context, w http.ResponseWriter, response interface{}) error {
		res := response.(authorizeTokenResponse)
		if res.Err != nil {
			return businessErrorEncoder(ctx, res.Err, w)
		}

		w.Header().Add(accessTokenHeader, res.Token)
		if res.Session != nil {
			if res.Session.Payload != nil {
				payload := base64.StdEncoding.EncodeToString(res.Session.Payload)
				w.Header().Add(payloadHeader, payload)
			}

			res.Session.Policies = nil
			res.Session.Payload = nil
			s, _ := json.Marshal(res.Session)
			enc := base64.StdEncoding.EncodeToString(s)
			w.Header().Add(sessionHeader, enc)
		}

		defer helpers.TraceStatusAndFinish(ctx, w.Header(), 204)
		w.WriteHeader(204)
		return nil
	}
}

// DecodeHTTPRedirectRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPRedirectRequest(requestURLHeader string) httptransport.DecodeRequestFunc {
	return func(_ context.Context, r *http.Request) (interface{}, error) {
		hostname := ""
		requestURL := r.Header.Get(requestURLHeader)
		if u, err := url.ParseRequestURI(requestURL); err == nil {
			hostname = u.Host
		}
		return redirectRequest{
			RequestURL: requestURL,
			Hostname:   hostname,
		}, nil
	}
}

// EncodeHTTPRedirectResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPRedirectResponse(redirectURLHeader, redirectURLQueryParam string) httptransport.EncodeResponseFunc {
	return func(ctx context.Context, w http.ResponseWriter, response interface{}) error {
		res := response.(redirectResponse)
		if res.Err != nil {
			return businessErrorEncoder(ctx, res.Err, w)
		}
		w.Header().Add("Location", fmt.Sprintf("%s?%s=%s", res.RedirectURL, redirectURLQueryParam, res.RequestURL))
		w.Header().Add(redirectURLHeader, res.RequestURL)

		defer helpers.TraceStatusAndFinish(ctx, w.Header(), 307)
		w.WriteHeader(307)
		return nil
	}
}

func businessErrorEncoder(ctx context.Context, err error, w http.ResponseWriter) error {
	var apiError helpers.APIError
	if isErrDeniedAccess(err) {
		apiError = helpers.APIUnauthorized
	} else {
		return err
	}

	defer helpers.TraceAPIErrorAndFinish(ctx, w.Header(), apiError)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiError.Status)
	json.NewEncoder(w).Encode(apiError)
	return nil
}
