package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile reads and parses a policy YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses raw YAML bytes into a Policy.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := validate(&p); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}
	return &p, nil
}

// validate checks the policy for logical errors.
func validate(p *Policy) error {
	if p.Agent == "" {
		return fmt.Errorf("agent name is required")
	}

	for i, s := range p.Secrets {
		if s.Name == "" {
			return fmt.Errorf("secret[%d]: name is required", i)
		}
		for _, u := range s.Use {
			switch u {
			case "network", "env":
			default:
				return fmt.Errorf("secret[%d] %q: invalid use %q (allowed: network, env)", i, s.Name, u)
			}
		}
	}

	for i, r := range p.Network.Allow {
		if err := validateNetRule("allow", i, r); err != nil {
			return err
		}
	}
	for i, r := range p.Network.Deny {
		if err := validateNetRule("deny", i, r); err != nil {
			return err
		}
	}

	return nil
}
