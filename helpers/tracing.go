package helpers

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	httptransport "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

func FromHTTPRequest(tracer stdopentracing.Tracer, operationName string, logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		ctx = opentracing.FromHTTPRequest(tracer, operationName, logger)(ctx, r)
		if span := stdopentracing.SpanFromContext(ctx); span != nil {
			buf := bytes.NewBuffer(nil)
			body, _ := ioutil.ReadAll(io.TeeReader(r.Body, buf))
			r.Body = ioutil.NopCloser(buf)
			span = span.SetTag("transport", "HTTP")
			span = span.SetTag("req.body", string(body))
			span = span.SetTag("req.method", r.Method)
			span = span.SetTag("req.url", r.URL.String())
			span = span.SetTag("req.remote", r.RemoteAddr)
			span = span.SetTag("req.agent", r.UserAgent())
			ctx = stdopentracing.ContextWithSpan(ctx, span)
		}
		return ctx
	}
}

func TraceStatusAndFinish(ctx context.Context, status int) {
	if span := stdopentracing.SpanFromContext(ctx); span != nil {
		span = span.SetTag("res.status", status)
		span.Finish()
	}
}

func TraceAPIErrorAndFinish(ctx context.Context, err APIError) {
	if span := stdopentracing.SpanFromContext(ctx); span != nil {
		if span := stdopentracing.SpanFromContext(ctx); span != nil {
			span = span.SetTag("res.status", err.Status)
			span = span.SetTag("res.description", err.Description)
			span = span.SetTag("res.errorCode", err.ErrorCode)
			span = span.SetTag("res.params", err.Params)
			span.Finish()
		}
	}
}

func TraceError(ctx context.Context, err error) {
	if span := stdopentracing.SpanFromContext(ctx); span != nil {
		type stackTracer interface {
			StackTrace() errors.StackTrace
		}
		if e, ok := err.(stackTracer); ok {
			st := e.StackTrace()[0]
			split := strings.Split(fmt.Sprintf("%+v", st), "\t")
			if len(split) == 2 {
				span = span.SetTag("errorLocation", split[1])
			}
		}
		span = span.SetTag("error", err.Error())
	}
}

func EndpointTracingMiddleware(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		defer func() {
			if err != nil {
				TraceError(ctx, err)
			}
		}()
		return next(ctx, request)
	}
}
