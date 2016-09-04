package config_test

import (
	"reflect"
	"testing"

	"github.com/solher/styx/config"
	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
)

func boolCpy(b bool) *bool { return &b }

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
		name   string         // Test case name
		file   string         // Input file
		config *config.Config // Expected result
		err    bool           // Expected error presence
	}{
		{name: "empty file", file: emptyFile, config: emptyConfig, err: false},
		{name: "example file", file: exampleFile, config: exampleConfig, err: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := config.FromFile([]byte(tc.file))

			if (err != nil) != tc.err {
				t.Errorf(`expected err presence to be %v, got "%s"`, tc.err, err)
			}
			if !reflect.DeepEqual(config, tc.config) {
				t.Errorf(`expected config to be %v, got %v`, tc.config, config)
			}
		})
	}
}
