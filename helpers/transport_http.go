package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	stdopentracing "github.com/opentracing/opentracing-go"
)

// APIError defines a standard format for API errors.
type APIError struct {
	// The status code.
	Status int `json:"status"`
	// The description of the API error.
	Description string `json:"description"`
	// The token uniquely identifying the API error.
	ErrorCode string `json:"errorCode"`
	// Additional infos.
	Params map[string]interface{} `json:"params,omitempty"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("%s : %s", e.ErrorCode, e.Description)
}

var (
	ErrInternal = APIError{
		Status:      500,
		Description: "An internal error occured. Please retry later.",
		ErrorCode:   "INTERNAL_ERROR",
	}
	ErrBodyDecoding = APIError{
		Status:      400,
		Description: "Could not decode the JSON request.",
		ErrorCode:   "BODY_DECODING_ERROR",
	}
	ErrForbidden = APIError{
		Status:      403,
		Description: "The specified resource was not found or you don't have sufficient permissions.",
		ErrorCode:   "FORBIDDEN",
	}
	ErrValidation = APIError{
		Status:      422,
		Description: "The model validation failed.",
		ErrorCode:   "VALIDATION_ERROR",
	}
)

func EncodeAPIError(ctx context.Context, err APIError, w http.ResponseWriter) error {
	defer func() {
		if span := stdopentracing.SpanFromContext(ctx); span != nil {
			span = span.SetTag("res.status", err.Status)
			span = span.SetTag("res.description", err.Description)
			span = span.SetTag("res.errorCode", err.ErrorCode)
			span = span.SetTag("res.params", err.Params)
			span.Finish()
		}
	}()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(err.Status)
	return json.NewEncoder(w).Encode(err)
}

func EncodeHTTPHeaders(ctx context.Context, w http.ResponseWriter, status int) {
	defer func() {
		if span := stdopentracing.SpanFromContext(ctx); span != nil {
			span = span.SetTag("res.status", status)
			span.Finish()
		}
	}()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
}
