package memory

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/solher/styx/helpers"
	"github.com/solher/styx/resources"
)

type errResourceNotFound struct {
	helpers.ErrBehavior
	errNotFoundBehavior
}

func newErrResourceNotFound(msg string) (err errResourceNotFound) {
	defer func() { err.Msg = msg }()
	return errResourceNotFound{}
}

type (
	resourceHostname string
	resourceStore    map[resourceHostname]*resources.Resource
)

type resourceRepository struct {
	mtx       sync.RWMutex
	resources resourceStore
}

// SetResources replace the current resource store with the given new resources.
func SetResources(repo resources.Repository, resources []resources.Resource) error {
	r, ok := repo.(*resourceRepository)
	if !ok {
		return errors.New("unexpected type")
	}
	store := resourceStore{}
	for _, resource := range resources {
		store[resourceHostname(resource.Hostname)] = &resource
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.resources = store
	return nil
}

// NewResourceRepository returns a new instance of a in-memory resource repository.
func NewResourceRepository() resources.Repository {
	return &resourceRepository{
		resources: make(map[resourceHostname]*resources.Resource),
	}
}

// FindByHostname finds a resource by its hostname and returns it.
func (r *resourceRepository) FindByHostname(ctx context.Context, hostname string) (*resources.Resource, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	resource, ok := r.resources[resourceHostname(hostname)]
	if !ok {
		return nil, newErrResourceNotFound("resource resource not found")
	}
	return resource, nil
}
