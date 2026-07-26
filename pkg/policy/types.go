package policy

// Policy represents the full agent sandboxing policy.
type Policy struct {
	Agent      string          `yaml:"agent"`
	Secrets    []SecretPolicy  `yaml:"secrets"`
	Network    NetworkPolicy   `yaml:"network"`
	Filesystem FSPolicy        `yaml:"filesystem"`
	Exec       ExecPolicy      `yaml:"exec"`
}

// SecretPolicy defines how a secret can be used.
type SecretPolicy struct {
	Name string   `yaml:"name"`
	Use  []string `yaml:"use"`  // "network", "env"
	Read bool     `yaml:"read"` // whether agent can read raw value
}

// NetworkPolicy defines allowed/denied network destinations.
type NetworkPolicy struct {
	Allow []NetworkRule `yaml:"allow"`
	Deny  []NetworkRule `yaml:"deny"`
}

// NetworkRule is a single network allow/deny entry.
type NetworkRule struct {
	Host  string `yaml:"host,omitempty"`
	CIDR  string `yaml:"cidr,omitempty"`
	Port  int    `yaml:"port,omitempty"`
	Ports []int  `yaml:"ports,omitempty"`
}

// FSPolicy defines filesystem access rules.
type FSPolicy struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
	Deny  []string `yaml:"deny"`
}

// ExecPolicy defines which binaries can be executed.
type ExecPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}
