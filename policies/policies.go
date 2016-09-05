package policies

import "context"

// Policy represents a set of permissions, assignable to a session.
type Policy struct {
	// The policy name.
	Name string `json:"name,omitempty" yaml:"name"`
	// Can be used to disable a policy.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled"`
	// An array of resource and their associated right.
	Permissions []Permission `json:"permissions,omitempty" yaml:"permissions"`
}

// Permission is the association of a resource and a right.
type Permission struct {
	// The resource name concerned by the permission.
	Resource string `json:"resource,omitempty" yaml:"resource"`
	// The optional paths on which the permission apply.
	Paths []string `json:"paths,omitempty" yaml:"paths"`
	// Can be used to disable a permission.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled"`
	// Indicates if the permission grants or denies the access on the resource.
	Deny *bool `json:"deny,omitempty" yaml:"deny"`
}

// Repository provides access to a policy store.
type Repository interface {
	FindByName(ctx context.Context, name string) (*Policy, error)
}
