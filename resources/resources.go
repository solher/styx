package resources

import (
	"context"

	"github.com/solher/styx/helpers"
)

// Resource represents a host defined by his hostname.
type Resource struct {
	// The resource name. Must be unique.
	Name string `json:"name,omitempty" yaml:"name"`
	// The resource host name. Ex: 'resource.example.com'
	Hostname string `json:"hostname,omitempty" yaml:"hostname"`
	// Disable the authentication for that resource.
	Public *bool `json:"public,omitempty" yaml:"public"`
	// The redirection URL when access is denied to the resource.
	RedirectURL string `json:"redirectUrl,omitempty" yaml:"redirectUrl"`
}

// Repository provides access to a resource store.
type Repository interface {
	FindByHostname(ctx context.Context, hostname string) (*Resource, error)
}

// ErrNotFound is used when a resource could not be found.
type ErrNotFound struct{ helpers.BasicError }

// NewErrNotFound returns a new instance of ErrNotFound.
func NewErrNotFound(msg string) ErrNotFound {
	return ErrNotFound{BasicError: helpers.NewBasicError(msg)}
}
