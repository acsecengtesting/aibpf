package policy

import (
	"testing"
)

const validPolicy = `
agent: my-code-agent
secrets:
  - name: OPENAI_API_KEY
    use: [network]
    read: false
  - name: DB_PASSWORD
    use: [network]
    read: false

network:
  allow:
    - host: api.openai.com
      ports: [443]
    - host: github.com
      ports: [443]
  deny:
    - cidr: 169.254.169.254/32
    - port: 25

filesystem:
  read: ["/workspace/**", "/tmp/**"]
  write: ["/workspace/**", "/tmp/**"]
  deny: ["/etc/shadow", "/proc/*/mem"]

exec:
  allow: [python3, node, git, curl]
  deny: [nc, ncat, "bash -i"]
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.Agent != "my-code-agent" {
		t.Errorf("agent = %q, want %q", p.Agent, "my-code-agent")
	}

	if len(p.Secrets) != 2 {
		t.Errorf("secrets count = %d, want 2", len(p.Secrets))
	}

	if p.Secrets[0].Name != "OPENAI_API_KEY" {
		t.Errorf("secret[0].name = %q, want %q", p.Secrets[0].Name, "OPENAI_API_KEY")
	}

	if p.Secrets[0].Read != false {
		t.Error("secret[0].read should be false")
	}

	if len(p.Network.Allow) != 2 {
		t.Errorf("network.allow count = %d, want 2", len(p.Network.Allow))
	}

	if p.Network.Allow[0].Host != "api.openai.com" {
		t.Errorf("allow[0].host = %q, want %q", p.Network.Allow[0].Host, "api.openai.com")
	}

	if len(p.Network.Deny) != 2 {
		t.Errorf("network.deny count = %d, want 2", len(p.Network.Deny))
	}

	if p.Network.Deny[0].CIDR != "169.254.169.254/32" {
		t.Errorf("deny[0].cidr = %q, want 169.254.169.254/32", p.Network.Deny[0].CIDR)
	}

	if len(p.Exec.Allow) != 4 {
		t.Errorf("exec.allow count = %d, want 4", len(p.Exec.Allow))
	}

	if len(p.Filesystem.Read) != 2 {
		t.Errorf("filesystem.read count = %d, want 2", len(p.Filesystem.Read))
	}
}

func TestParseNoAgent(t *testing.T) {
	_, err := Parse([]byte(`
network:
  allow:
    - host: foo.com
      ports: [443]
`))
	if err == nil {
		t.Fatal("expected error for missing agent")
	}
}

func TestParseInvalidCIDR(t *testing.T) {
	yaml := `
agent: test
network:
  deny:
    - cidr: not-a-cidr
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParseInvalidSecretUse(t *testing.T) {
	yaml := `
agent: test
secrets:
  - name: X
    use: [invalid]
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid secret use")
	}
}

func TestParseEmptyNetRule(t *testing.T) {
	yaml := `
agent: test
network:
  allow:
    - {}
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for empty network rule")
	}
}

func TestParseValidMinimal(t *testing.T) {
	yaml := `
agent: minimal-agent
network:
  allow:
    - host: example.com
      ports: [80]
`
	p, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Agent != "minimal-agent" {
		t.Errorf("agent = %q, want minimal-agent", p.Agent)
	}
}
