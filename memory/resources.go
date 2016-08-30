package memory

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/solher/styx/resources"
)

type resourceStore map[resources.Hostname]*resources.Resource

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
		store[resource.Hostname] = &resource
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.resources = store
	return nil
}

// NewResourceRepository returns a new instance of a in-memory resource repository.
func NewResourceRepository() resources.Repository {
	return &resourceRepository{
		resources: make(map[resources.Hostname]*resources.Resource),
	}
}

// FindByHostname finds a resource by its hostname and returns it.
func (r *resourceRepository) FindByHostname(hostname resources.Hostname) (*resources.Resource, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	resource, ok := r.resources[hostname]
	if !ok {
		return nil, resources.ErrNotFound
	}
	return resource, nil
}
