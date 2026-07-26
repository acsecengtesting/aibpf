package policy

import (
	"fmt"
	"net"
)

func validateNetRule(kind string, idx int, r NetworkRule) error {
	if r.Host == "" && r.CIDR == "" && r.Port == 0 {
		return fmt.Errorf("network.%s[%d]: must specify host, cidr, or port", kind, idx)
	}
	if r.CIDR != "" {
		if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
			return fmt.Errorf("network.%s[%d]: invalid cidr %q: %w", kind, idx, r.CIDR, err)
		}
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("network.%s[%d]: invalid port %d", kind, idx, r.Port)
	}
	for j, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("network.%s[%d].ports[%d]: invalid port %d", kind, idx, j, p)
		}
	}
	return nil
}
