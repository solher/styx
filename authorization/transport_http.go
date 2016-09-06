package authorization

import (
	"encoding/base64"
	"encoding/json"
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
		accessTokenCookie: "access_token",
		accessTokenHeader: "Styx-Access-Token",
		requestURLHeader:  "Request-Url",
	}
	for _, opt := range opts {
		opt(handlerOpts)
	}

	authorizeTokenHandler := httptransport.NewServer(
		ctx,
		endpoints.AuthorizeTokenEndpoint,
		DecodeHTTPAuthorizeTokenRequest(handlerOpts.accessTokenCookie, handlerOpts.accessTokenHeader, handlerOpts.requestURLHeader),
		EncodeHTTPAuthorizeTokenResponse,
		append(transportOpts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Authorize token", logger)))...,
	)
	redirectHandler := httptransport.NewServer(
		ctx,
		endpoints.RedirectEndpoint,
		DecodeHTTPRedirectRequest,
		EncodeHTTPRedirectResponse,
		append(transportOpts, httptransport.ServerBefore(helpers.FromHTTPRequest(tracer, "Redirect URL", logger)))...,
	)

	r := chi.NewRouter()
	r.Post("/authorizeToken", authorizeTokenHandler.ServeHTTP)
	r.Get("/redirect", redirectHandler.ServeHTTP)

	return r
}

type httpHandlerOptions struct {
	accessTokenCookie string
	accessTokenHeader string
	requestURLHeader  string
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
func EncodeHTTPAuthorizeTokenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(authorizeTokenResponse)
	if res.Err != nil {
		return businessErrorEncoder(ctx, res.Err, w)
	}

	w.Header().Add("Styx-Access-Token", res.Token)
	if res.Session != nil {
		if res.Session.Payload != nil {
			payload := base64.StdEncoding.EncodeToString(res.Session.Payload)
			w.Header().Add("Styx-Payload", payload)
		}

		res.Session.Policies = nil
		res.Session.Payload = nil
		s, _ := json.Marshal(res.Session)
		enc := base64.StdEncoding.EncodeToString(s)
		w.Header().Add("Styx-Session", enc)
	}

	defer helpers.TraceStatusAndFinish(ctx, 204)
	w.WriteHeader(204)
	return nil
}

// DecodeHTTPRedirectRequest is a transport/http.DecodeRequestFunc that decodes the
// JSON-encoded request from the HTTP request body.
func DecodeHTTPRedirectRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	hostname := ""
	requestURL := r.Header.Get("Request-Url")
	if u, err := url.ParseRequestURI(requestURL); err == nil {
		hostname = u.Host
	}
	return redirectRequest{
		RequestURL: requestURL,
		Hostname:   hostname,
	}, nil
}

// EncodeHTTPRedirectResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer.
func EncodeHTTPRedirectResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(redirectResponse)
	if res.Err != nil {
		return businessErrorEncoder(ctx, res.Err, w)
	}
	w.Header().Add("Location", res.RedirectURL+"?redirectUrl="+res.RequestURL)
	w.Header().Add("Redirect-Url", res.RequestURL)

	defer helpers.TraceStatusAndFinish(ctx, 307)
	w.WriteHeader(307)
	return nil
}

func businessErrorEncoder(ctx context.Context, err error, w http.ResponseWriter) error {
	var apiError helpers.APIError
	if isErrDeniedAccess(err) {
		apiError = helpers.APIUnauthorized
	} else {
		return err
	}

	defer helpers.TraceAPIErrorAndFinish(ctx, apiError)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiError.Status)
	json.NewEncoder(w).Encode(apiError)
	return nil
}
