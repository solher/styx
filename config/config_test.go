package config_test

import (
	"errors"
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
	var tests = []struct {
		file   string         // Input file
		config *config.Config // Expected result
		err    bool           // Expected error presence
	}{
		{file: emptyFile, config: emptyConfig, err: false},
		{file: exampleFile, config: exampleConfig, err: false},
	}

	for i, test := range tests {
		config, err := config.FromFile([]byte(test.file))

		errPresent := (err != nil)
		if !errPresent {
			err = errors.New("nil")
		}
		if errPresent != test.err {
			t.Errorf(`Test %d: expected err presence to be %v, got "%s"`, i, test.err, err.Error())
		}

		if !reflect.DeepEqual(config, test.config) {
			t.Errorf(`Test %d: expected config to be %v, got %v`, i, test.config, config)
		}
	}
}
