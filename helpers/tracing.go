package helpers

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	httptransport "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
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

func TraceError(ctx context.Context, err error) {
	if span := stdopentracing.SpanFromContext(ctx); span != nil {
		span = span.SetTag("error", err.Error())
		ctx = stdopentracing.ContextWithSpan(ctx, span)
	}
}
