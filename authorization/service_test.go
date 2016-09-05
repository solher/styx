package authorization_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/solher/styx/authorization"
	"github.com/solher/styx/helpers"
	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
	"github.com/solher/styx/sessions"
)

var (
	simpleResource = &resources.Resource{
		Name:     "Foobar",
		Hostname: "foo.bar.com",
	}

	simplePublicResource = &resources.Resource{
		Name:     "Foobar",
		Hostname: "foo.bar.com",
		Public:   boolCpy(true),
	}
)

var (
	emptyPoliciesSession = &sessions.Session{
		Token: "F00bAr",
	}

	onePolicySession = &sessions.Session{
		Token:    "F00bAr",
		Policies: []string{"Foo"},
	}
)

var (
	simpleGrantPolicy = &policies.Policy{
		Name: "Foo",
		Permissions: []policies.Permission{
			{Resource: "Foobar"},
		},
	}

	twoResourcesPolicy = &policies.Policy{
		Name: "Foo",
		Permissions: []policies.Permission{
			{Resource: "Foobar"},
			{Resource: "Foobar2"},
		},
	}

	deniedPathsPolicy = &policies.Policy{
		Name: "Foo",
		Permissions: []policies.Permission{
			{
				Resource: "Foobar",
			},
			{
				Resource: "Foobar",
				Paths:    []string{"/bar", "/bar2"},
				Deny:     boolCpy(true),
			},
		},
	}

	wildcardDeniedPathPolicy = &policies.Policy{
		Name: "Foo",
		Permissions: []policies.Permission{
			{
				Resource: "Foobar",
			},
			{
				Resource: "Foobar",
				Paths:    []string{"/foo/*"},
				Deny:     boolCpy(true),
				Enabled:  boolCpy(true),
			},
		},
	}

	emptyPermissionsPolicy = &policies.Policy{
		Name:        "Foo",
		Permissions: []policies.Permission{},
	}

	guestPolicy = &policies.Policy{
		Name:    "guest",
		Enabled: boolCpy(true),
		Permissions: []policies.Permission{
			{
				Resource: "Foobar",
				Paths:    []string{"/*"},
			},
		},
	}
)

// TestAuthorizeToken runs tests on the AuthorizeToken function.
func TestAuthorizeToken(t *testing.T) {
	var testCases = []struct {
		name string // Test case name

		hostname string // Input hostname
		path     string // Input path
		token    string // Input token

		policyRepoFindByNamePolicy         *policies.Policy    // Policy returned by the policy repo FindByName method
		policyRepoFindByNameError          error               // Error returned by the policy repo FindByName method
		resourceRepoFindByHostnameResource *resources.Resource // Resource returned by the resource repo FindByHostname method
		resourceRepoFindByHostnameError    error               // Error returned by the resource repo FindByHostname method
		sessionRepoFindByTokenSession      *sessions.Session   // Session returned by the session repo FindByToken method
		sessionRepoFindByTokenError        error               // Error returned by the session repo FindByToken method

		session       *sessions.Session // Expected result
		errorExpected bool              // Expected error presence
		err           error             // Expected error (ignored if errorExpected == true and error == nil)
	}{
		{
			name:     "no policies in session",
			hostname: simpleResource.Hostname, path: "", token: "F00bAr",
			policyRepoFindByNamePolicy: simpleGrantPolicy, policyRepoFindByNameError: nil,
			resourceRepoFindByHostnameResource: simpleResource, resourceRepoFindByHostnameError: nil,
			sessionRepoFindByTokenSession: emptyPoliciesSession, sessionRepoFindByTokenError: nil,
			session: nil, errorExpected: true,
		},
		{
			name:     "no permissions in policy",
			hostname: simpleResource.Hostname, path: "", token: "F00bAr",
			policyRepoFindByNamePolicy:         emptyPermissionsPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            nil, errorExpected: true,
		},
		{
			name:     "simple grant",
			hostname: simpleResource.Hostname, path: "", token: "F00bAr",
			policyRepoFindByNamePolicy:         simpleGrantPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            onePolicySession, errorExpected: false,
		},
		{
			name:     "path denied",
			hostname: simpleResource.Hostname, path: "/bar2", token: "F00bAr",
			policyRepoFindByNamePolicy:         deniedPathsPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            nil, errorExpected: true,
		},
		{
			name:     "path granted because of public resource",
			hostname: simplePublicResource.Hostname, path: "/bar2", token: "F00bAr",
			policyRepoFindByNamePolicy:         deniedPathsPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simplePublicResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            nil, errorExpected: false,
		},
		{
			name:     "wildcarded path denied",
			hostname: simpleResource.Hostname, path: "/foo/abc/def", token: "F00bAr",
			policyRepoFindByNamePolicy:         wildcardDeniedPathPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            nil, errorExpected: true,
		},
		{
			name:     "trailing slash escaped",
			hostname: simpleResource.Hostname, path: "/foo/", token: "F00bAr",
			policyRepoFindByNamePolicy:         wildcardDeniedPathPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      onePolicySession,
			sessionRepoFindByTokenError:        nil,
			session:                            onePolicySession, errorExpected: false,
		},
		{
			name:     "guest policy does not exists",
			hostname: simpleResource.Hostname, path: "", token: "F00bAr",
			policyRepoFindByNamePolicy:         nil,
			policyRepoFindByNameError:          newErrNotFound("policy not found"),
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      nil,
			sessionRepoFindByTokenError:        newErrNotFound("session not found"),
			session:                            nil, errorExpected: true,
		},
		{
			name:     "guest policy grant",
			hostname: simpleResource.Hostname, path: "", token: "F00bAr",
			policyRepoFindByNamePolicy:         guestPolicy,
			policyRepoFindByNameError:          nil,
			resourceRepoFindByHostnameResource: simpleResource,
			resourceRepoFindByHostnameError:    nil,
			sessionRepoFindByTokenSession:      nil,
			sessionRepoFindByTokenError:        newErrNotFound("session not found"),
			session:                            nil, errorExpected: false,
		},
	}

	policyRepo, resourceRepo, sessionRepo := &policyRepo{}, &resourceRepo{}, &sessionRepo{}
	service := authorization.NewService(policyRepo, resourceRepo, sessionRepo)
	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policyRepo.findByNamePolicy, policyRepo.findByNameError = tc.policyRepoFindByNamePolicy, tc.policyRepoFindByNameError
			resourceRepo.findByHostnameResource, resourceRepo.findByHostnameError = tc.resourceRepoFindByHostnameResource, tc.resourceRepoFindByHostnameError
			sessionRepo.findByTokenSession, sessionRepo.findByTokenError = tc.sessionRepoFindByTokenSession, tc.sessionRepoFindByTokenError
			session, err := service.AuthorizeToken(ctx, tc.hostname, tc.path, tc.token)

			if tc.errorExpected != (err != nil) {
				t.Errorf(`expected err presence to be "%v", got "%s"`, format(tc.errorExpected), format(err))
			}
			if !reflect.DeepEqual(session, tc.session) {
				t.Errorf(`expected session to be "%v", got "%v"`, format(tc.session), format(session))
			}
		})
	}
}

type errNotFoundBehavior struct{}

func (err errNotFoundBehavior) IsErrNotFound() {}

type errNotFound struct {
	helpers.ErrBehavior
	errNotFoundBehavior
}

func newErrNotFound(msg string) (err errNotFound) {
	defer func() { err.Msg = msg }()
	return errNotFound{}
}

func format(v interface{}) string {
	if v == nil {
		return "nil"
	}
	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Array, reflect.Slice:
		if val.IsNil() {
			return "nil"
		}
	}
	switch t := v.(type) {
	case error:
		return t.Error()
	default:
		m, _ := json.Marshal(v)
		return string(m)
	}
}

func boolCpy(b bool) *bool { return &b }

type policyRepo struct {
	findByNamePolicy *policies.Policy
	findByNameError  error
}

func (r *policyRepo) FindByName(ctx context.Context, name string) (*policies.Policy, error) {
	return r.findByNamePolicy, r.findByNameError
}

type resourceRepo struct {
	findByHostnameResource *resources.Resource
	findByHostnameError    error
}

func (r *resourceRepo) FindByHostname(ctx context.Context, hostname string) (*resources.Resource, error) {
	return r.findByHostnameResource, r.findByHostnameError
}

type sessionRepo struct {
	findByTokenSession *sessions.Session
	findByTokenError   error
}

func (r *sessionRepo) FindByToken(ctx context.Context, token string) (*sessions.Session, error) {
	return r.findByTokenSession, r.findByTokenError
}
