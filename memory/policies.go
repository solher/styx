package memory

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/solher/styx/policies"
)

type (
	policyName  string
	policyStore map[policyName]*policies.Policy
)

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
		store[policyName(policy.Name)] = &policy
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.policies = store
	return nil
}

// NewPolicyRepository returns a new instance of a in-memory policy repository.
func NewPolicyRepository() policies.Repository {
	return &policyRepository{
		policies: make(map[policyName]*policies.Policy),
	}
}

// FindByName finds a policy by its name and returns it.
func (r *policyRepository) FindByName(ctx context.Context, name string) (*policies.Policy, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	policy, ok := r.policies[policyName(name)]
	if !ok {
		return nil, policies.ErrNotFound
	}
	return policy, nil
}
