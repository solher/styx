package config

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/solher/styx/policies"
	"github.com/solher/styx/resources"
	"gopkg.in/yaml.v2"
)

// Config represents a parsed configuration file.
type Config struct {
	Resources []resources.Resource `json:"resources" yaml:"resources"`
	Policies  []policies.Policy    `json:"policies" yaml:"policies"`
}

// FromFile parses and validates a configuration file.
func FromFile(file []byte) (*Config, error) {
	config := &Config{}
	if errYAML := yaml.Unmarshal(file, config); errYAML != nil {
		if errJSON := json.Unmarshal(file, config); errJSON != nil {
			return nil, errors.New("could not parse the config file: YAML: " + errYAML.Error() + ", JSON: " + errJSON.Error())
		}
	}

	// We use name and hostname maps to test uniqueness
	resourceNames := make(map[string]struct{})
	resourceHostnames := make(map[string]struct{})
	resourceValidator := validateResource(resourceNames, resourceHostnames)
	if config.Resources != nil {
		for _, resource := range config.Resources {
			if err := resourceValidator(&resource); err != nil {
				return nil, err
			}
			resourceNames[resource.Name] = struct{}{}
			resourceHostnames[resource.Hostname] = struct{}{}
		}
	}

	// We use a name map to test uniqueness
	policyNames := make(map[string]struct{})
	policyValidator := validatePolicy(policyNames, resourceNames)
	if config.Policies != nil {
		for _, policy := range config.Policies {
			if err := policyValidator(&policy); err != nil {
				return nil, err
			}
			policyNames[policy.Name] = struct{}{}
		}
	}

	return config, nil
}

func validateResource(names, hostnames map[string]struct{}) func(resource *resources.Resource) error {
	return func(resource *resources.Resource) error {
		if len(resource.Name) == 0 {
			return errors.Errorf("resource name cannot be blank")
		}
		if len(resource.Hostname) == 0 {
			return errors.Errorf(`resource '%s' hostname cannot be blank`, resource.Name)
		}
		if _, exists := names[resource.Name]; exists {
			return errors.Errorf(`resource '%s' name must be unique`, resource.Name)
		}
		if _, exists := hostnames[resource.Hostname]; exists {
			return errors.Errorf(`resource '%s' hostname must be unique`, resource.Name)
		}
		return nil
	}
}

func validatePolicy(names, resourceNames map[string]struct{}) func(policy *policies.Policy) error {
	return func(policy *policies.Policy) error {
		if len(policy.Name) == 0 {
			return errors.Errorf("policy name cannot be blank")
		}
		if policy.Permissions == nil || len(policy.Permissions) == 0 {
			return errors.Errorf(`policy '%s' permissions cannot be blank`, policy.Name)
		}
		if _, exists := names[policy.Name]; exists {
			return errors.Errorf(`policy '%s' name must be unique`, policy.Name)
		}
		for _, permission := range policy.Permissions {
			if len(permission.Resource) == 0 {
				return errors.Errorf(`policy '%s': resource cannot be blank`, policy.Name)
			}
			if permission.Resource == "*" {
				continue
			}
			if _, exists := resourceNames[permission.Resource]; !exists {
				return errors.Errorf(`policy '%s': resource '%s' does not exists`, policy.Name, permission.Resource)
			}
		}
		return nil
	}
}
