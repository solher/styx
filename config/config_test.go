package config_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/solher/styx/config"
	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
)

var (
	emptyFile   = ``
	emptyConfig = &config.Config{}
)

var (
	exampleFile = `
resources:
  - name: host1
    hostname: host1.foobar.com
    public: true 
  - name: host2
    hostname: host2.foobar.com
    redirectUrl: http://www.google.com
  - name: host3
    hostname: host3.foobar.com
    public: false

policies:
  - name: guest
    enabled: true
    permissions: 
      - resource: host2
        deny: true
      - resource: host2 
        paths:
          - /foo/*
          - /bar
  - name: admin
    permissions:
      - resource: "*"
        enabled: false
`
	exampleConfig = &config.Config{
		Resources: []resources.Resource{
			{Name: "host1", Hostname: "host1.foobar.com", Public: boolCpy(true)},
			{Name: "host2", Hostname: "host2.foobar.com", RedirectURL: "http://www.google.com"},
			{Name: "host3", Hostname: "host3.foobar.com", Public: boolCpy(false)},
		},
		Policies: []policies.Policy{
			{Name: "guest", Enabled: boolCpy(true), Permissions: []policies.Permission{
				{Resource: "host2", Deny: boolCpy(true)},
				{Resource: "host2", Paths: []string{"/foo/*", "/bar"}},
			}},
			{Name: "admin", Permissions: []policies.Permission{
				{Resource: "*", Enabled: boolCpy(false)},
			}},
		},
	}
)

// TestFromFile runs tests on the FromFile function.
func TestFromFile(t *testing.T) {
	var testCases = []struct {
		name string // Test case name

		file string // Input file

		config        *config.Config // Expected result
		errorExpected bool           // Expected error presence
		err           error          // Expected error (ignored if errorExpected == true and error == nil)
	}{
		{
			name:   "empty file",
			file:   emptyFile,
			config: emptyConfig, errorExpected: false,
		},
		{
			name:   "example file",
			file:   exampleFile,
			config: exampleConfig, errorExpected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := config.FromFile([]byte(tc.file))

			if tc.errorExpected && tc.err != nil && tc.err != errors.Cause(err) {
				t.Errorf(`expected err to be "%v", got "%s"`, format(tc.err), format(err))
			} else if tc.errorExpected != (err != nil) {
				t.Errorf(`expected err presence to be "%v", got "%s"`, format(tc.errorExpected), format(err))
			}
			if !reflect.DeepEqual(config, tc.config) {
				t.Errorf(`expected config to be "%v", got "%v"`, format(tc.config), format(config))
			}
		})
	}
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
