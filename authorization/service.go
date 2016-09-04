package authorization

import (
	"context"
	"strings"

	"github.com/pkg/errors"

	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
	"github.com/solher/styx/sessions"
)

// ErrDeniedAccess is returned when the access is denied to the user.
var ErrDeniedAccess = errors.New("session not found, expired or unauthorized access")

// Service represents the authorization service interface.
type Service interface {
	AuthorizeToken(ctx context.Context, hostname, path, token string) (*sessions.Session, error)
	Redirect(ctx context.Context, hostname string) (string, error)
}

type service struct {
	policyRepo   policies.Repository
	resourceRepo resources.Repository
	sessionRepo  sessions.Repository
}

// NewService returns a new instance of the authorization service.
func NewService(policyRepo policies.Repository, resourceRepo resources.Repository, sessionRepo sessions.Repository) Service {
	return &service{
		policyRepo:   policyRepo,
		resourceRepo: resourceRepo,
		sessionRepo:  sessionRepo,
	}
}

// Redirect returns the URL to which the user must be redirected in case of a denied
// access to the given hostname.
func (s *service) Redirect(ctx context.Context, hostname string) (string, error) {
	resource, err := s.resourceRepo.FindByHostname(ctx, hostname)
	if err != nil {
		return "", err
	}
	return resource.RedirectURL, nil
}

// AuthorizeToken authorizes a given token to access a given URL.
func (s *service) AuthorizeToken(ctx context.Context, hostname, path, token string) (*sessions.Session, error) {
	resourceCh, resourceErrCh := make(chan *resources.Resource, 1), make(chan error, 1)
	sessionCh, sessionErrCh := make(chan *sessions.Session, 1), make(chan error, 1)
	go func() {
		session, err := s.sessionRepo.FindByToken(ctx, token)
		if err != nil {
			sessionErrCh <- err
			close(sessionCh)
			return
		}
		sessionCh <- session
		close(sessionErrCh)
	}()
	go func() {
		resource, err := s.resourceRepo.FindByHostname(ctx, hostname)
		if err != nil {
			resourceErrCh <- err
			close(resourceCh)
			return
		}
		resourceCh <- resource
		close(resourceErrCh)
	}()
	// If we can't find a resource, we deny the access
	// Otherwise, the access is denied with an error
	if err := <-resourceErrCh; err != nil {
		switch errors.Cause(err) {
		case resources.ErrNotFound:
			return nil, errors.Wrap(ErrDeniedAccess, "resource not found")
		default:
			return nil, err
		}
	}
	resource := <-resourceCh
	// If the found resource is marked as public, we allow the access without condition
	if resource.Public != nil && *resource.Public {
		return nil, nil
	}
	// If no session is found for the token, we initiate a guest session
	// Otherwise, the access is denied with an error
	if err := <-sessionErrCh; err != nil {
		switch errors.Cause(err) {
		case sessions.ErrNotFound:
			return s.authorizeGuestSession(ctx, path, resource.Name)
		default:
			return nil, err
		}
	}
	// If a session is found, we try to authorize it
	return s.authorizeSession(ctx, path, resource.Name, <-sessionCh)
}

func (s *service) authorizeSession(ctx context.Context, path, resource string, session *sessions.Session) (*sessions.Session, error) {
	errCh := make(chan error, len(session.Policies))
	// We check concurrently the associated policies and the permissions associated
	for _, policyName := range session.Policies {
		go func(policyName string) {
			// We find the policy corresponding to the given name
			policy, err := s.policyRepo.FindByName(ctx, policyName)
			if err != nil {
				errCh <- err
			}
			// We check the permissions
			errCh <- s.checkPermissions(policy, path, resource, policyName)
		}(policyName)
	}
	// We don't wait for all the policies to be checked
	// We return as soon as we find a positive result
	for range session.Policies {
		if err := <-errCh; err == nil {
			return session, nil
		}
	}
	return nil, errors.Wrap(ErrDeniedAccess, "access denied")
}

func (s *service) authorizeGuestSession(ctx context.Context, path, resource string) (*sessions.Session, error) {
	// First, we find the guest policy
	policy, err := s.policyRepo.FindByName(ctx, "guest")
	if err != nil {
		return nil, errors.Wrap(ErrDeniedAccess, err.Error())
	}
	// We check the guest permissions
	if err := s.checkPermissions(policy, path, resource, "guest"); err != nil {
		return nil, errors.Wrap(ErrDeniedAccess, "access denied to guest session")
	}
	return nil, nil
}

func (s *service) checkPermissions(policy *policies.Policy, path, resource, policyName string) error {
	// If the policy is disabled, we skip it
	if policy.Enabled != nil && *policy.Enabled == false {
		return errors.New("policy disabled")
	}
	// "reqPath" is the splited path of the incoming request
	// We will use it to compare it with the permissions
	reqPath := splitPath(path)
	reqWeight := len(reqPath)
	// "granted" is the boolean value indicating if the access must be granted
	granted := false
	// "maxWeight" is used to ponderate the permissions
	// A permission with a higher weight will override others with a lower one
	// The weight is here the number of "segments" in a permission path
	//
	// Example:
	//   "/foo" -> weight 1
	//   "/foo/bar" -> weight 2
	maxWeight := 0
	// "wildcard" indicates if the current maxWeight was set by a permission with a wildcard
	// In that case, a regular permission with the same weight would override it
	wildcard := false
	// We now check each permission of the policy
	for _, permission := range policy.Permissions {
		// If the permission does not concern the requested resource, we skip it
		if permission.Resource != resource && permission.Resource != "*" {
			continue
		}
		// If the permission is disabled, we skip it
		if permission.Enabled != nil && *permission.Enabled == false {
			continue
		}
		// A nil paths is considered as a wildcard
		if permission.Paths == nil {
			permission.Paths = []string{"*"}
		}
		for _, path := range permission.Paths {
			// We get the splited path and the weight of the permission
			permPath := splitPath(path)
			permWeight := len(permPath)
			// If the weight of the permission is higher than the weight of the request, we skip it
			//
			// Example:
			//    Req: "/foo"
			//    Perm: "/foo/bar" -> Does not apply here
			if permWeight > reqWeight {
				continue
			}
			// We override the granted/maxWeight/wildcard variables if the paths match and:
			//   - Current permission weight is higher than the current maxWeight
			//   or
			//   - Current permission weight is equal to the current maxWeight but was set by a wildcard
			if ok, wc := match(reqPath, permPath); ok && ((permWeight > maxWeight) || (wildcard && permWeight == maxWeight)) {
				if permission.Deny == nil {
					granted = true
				} else {
					granted = !*permission.Deny
				}
				maxWeight = permWeight
				wildcard = wc
			}
		}
	}
	// We return the result
	if !granted {
		return errors.New("access denied")
	}
	return nil
}

func splitPath(path string) []string {
	return strings.Split(strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/"), "/")
}

func match(reqPath, permPath []string) (bool, bool) {
	for i, p := range permPath {
		switch p {
		case reqPath[i]:
			if i == len(permPath)-1 && len(permPath) < len(reqPath) {
				return false, false
			}
			continue
		case "*":
			return true, true
		default:
			return false, false
		}
	}
	return true, false
}
