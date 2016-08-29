package resources

import "errors"

// Hostname represents a resource hostname.
type Hostname string

// Resource represents a host defined by his hostname.
type Resource struct {
	// The resource name. Must be unique.
	Name string `json:"name,omitempty" yaml:"name"`
	// The resource host name. Ex: 'resource.example.com'
	Hostname Hostname `json:"hostname,omitempty" yaml:"hostname"`
	// Disable the authentication for that resource.
	Public *bool `json:"public,omitempty" yaml:"public"`
	// The redirection URL when access is denied to the resource.
	RedirectURL string `json:"redirectUrl,omitempty" yaml:"redirectUrl"`
}

// ErrNotFound is used when a resource could not be found.
var ErrNotFound = errors.New("resource not found")

// Repository provides access to a resource store.
type Repository interface {
	FindByHostname(hostname Hostname) (*Resource, error)
}
