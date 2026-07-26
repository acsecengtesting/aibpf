// Package secrets manages BPF-based secret injection.
// Secrets are loaded into BPF maps and injected in-kernel when the agent
// writes {{SECRET:NAME}} placeholders to sockets.
package secrets

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	MaxSecretNameLen  = 64
	MaxSecretValLen   = 128
	PlaceholderPrefix = "{{SECRET:"
	PlaceholderSuffix = "}}"
)

// SecretEntry matches the BPF struct secret_val.
type SecretEntry struct {
	Value [MaxSecretValLen]byte
	Len   uint32
}

// Injector manages secret lifecycle in BPF maps.
type Injector struct {
	secretMap *ebpf.Map
}

// NewInjector wraps an existing BPF map (from a loaded collection).
func NewInjector(m *ebpf.Map) *Injector {
	return &Injector{secretMap: m}
}

// LoadSecret adds a secret to the BPF map.
func (inj *Injector) LoadSecret(name, value string) error {
	if len(name) >= MaxSecretNameLen {
		return fmt.Errorf("secret name %q too long (max %d)", name, MaxSecretNameLen-1)
	}
	if len(value) > MaxSecretValLen {
		return fmt.Errorf("secret value for %q too long (max %d)", name, MaxSecretValLen)
	}

	// Placeholder length: {{SECRET:NAME}}
	placeholderLen := len(PlaceholderPrefix) + len(name) + len(PlaceholderSuffix)
	if len(value) > placeholderLen {
		return fmt.Errorf("secret %q value (%d bytes) longer than placeholder (%d bytes) — cannot rewrite in place",
			name, len(value), placeholderLen)
	}

	key := make([]byte, MaxSecretNameLen)
	copy(key, name)

	entry := SecretEntry{Len: uint32(len(value))}
	copy(entry.Value[:], value)

	return inj.secretMap.Put(key, entry)
}

// LoadSecretsFromFile reads a KEY=VALUE file and loads all secrets.
func (inj *Injector) LoadSecretsFromFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if err := inj.LoadSecret(k, v); err != nil {
			return count, fmt.Errorf("loading secret %q: %w", k, err)
		}
		count++
	}
	return count, nil
}

// Placeholder returns the placeholder string for a given secret name.
func Placeholder(name string) string {
	return PlaceholderPrefix + name + PlaceholderSuffix
}

// MaskedEnv returns environment variable entries where real values
// are replaced with placeholders. These are what the agent process sees.
func MaskedEnv(secrets map[string]string) []string {
	env := os.Environ()
	var result []string
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if ok {
			if _, isSecret := secrets[k]; isSecret {
				result = append(result, k+"="+Placeholder(k))
				continue
			}
		}
		result = append(result, e)
	}
	// Add placeholder entries for secrets not already in env
	for k := range secrets {
		found := false
		for _, e := range env {
			if strings.HasPrefix(e, k+"=") {
				found = true
				break
			}
		}
		if !found {
			result = append(result, k+"="+Placeholder(k))
		}
	}
	return result
}
