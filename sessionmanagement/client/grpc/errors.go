package grpc

import "github.com/pkg/errors"

var (
	// ErrNotFound is returned when the specified resource was not found.
	ErrNotFound = errors.New("the specified resource was not found or insufficient permissions")
	// ErrValidation is returned when the model/parameters validation failed.
	ErrValidation = errors.New("the request validation failed")
)
