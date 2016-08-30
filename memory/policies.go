package memory

import (
	"errors"
	"sync"

	"github.com/solher/styx/policies"
)

type policyStore map[policies.Name]*policies.Policy

type policyRepository struct {
	mtx      sync.RWMutex
	policies policyStore
}

// SetPolicies replace the current policy store with the given new policies.
func SetPolicies(repo policies.Repository, policies []policies.Policy) error {
	r, ok := repo.(*policyRepository)
	if !ok {
		return errors.New("unexpected type")
	}
	store := policyStore{}
	for _, policy := range policies {
		store[policy.Name] = &policy
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.policies = store
	return nil
}

// NewPolicyRepository returns a new instance of a in-memory policy repository.
func NewPolicyRepository() policies.Repository {
	return &policyRepository{
		policies: make(map[policies.Name]*policies.Policy),
	}
}

// FindByName finds a policy by its name and returns it.
func (r *policyRepository) FindByName(name policies.Name) (*policies.Policy, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	policy, ok := r.policies[name]
	if !ok {
		return nil, policies.ErrNotFound
	}
	return policy, nil
}
