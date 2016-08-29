package memory

import (
	"sync"

	"github.com/solher/styx/resources"
)

type resourceStore map[resources.Hostname]*resources.Resource

type resourceRepository struct {
	mtx       sync.RWMutex
	resources resourceStore
}

func (r *resourceRepository) setStore(resources resourceStore) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.resources = resources
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
