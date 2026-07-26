package bpf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/acsecengtesting/aibpf/pkg/policy"
)

// Programs holds loaded BPF programs and their links.
type Programs struct {
	NetworkProg *ebpf.Program
	ExecProg    *ebpf.Program
	ScrubProg   *ebpf.Program

	networkLink link.Link
	execLink    link.Link
	scrubLink   link.Link

	ExecReader  *perf.Reader
	ScrubReader *perf.Reader
}

// LoadAndAttach loads BPF object files and attaches them based on policy.
func LoadAndAttach(bpfDir string, cgroupPath string, pol *policy.Policy) (*Programs, error) {
	progs := &Programs{}

	// Load network BPF
	netObj := filepath.Join(bpfDir, "network.o")
	if _, err := os.Stat(netObj); err == nil {
		spec, err := ebpf.LoadCollectionSpec(netObj)
		if err != nil {
			return nil, fmt.Errorf("loading network.o: %w", err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return nil, fmt.Errorf("creating network collection: %w", err)
		}
		prog := coll.Programs["aibpf_connect4"]
		if prog == nil {
			return nil, fmt.Errorf("network.o: program aibpf_connect4 not found")
		}
		progs.NetworkProg = prog

		// Populate allow/deny maps
		if err := populateNetRules(coll, pol); err != nil {
			return nil, fmt.Errorf("populating network rules: %w", err)
		}

		// Attach to cgroup
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Program: prog,
			Attach:  ebpf.AttachCGroupInet4Connect,
		})
		if err != nil {
			return nil, fmt.Errorf("attaching network BPF: %w", err)
		}
		progs.networkLink = l
	}

	return progs, nil
}

// Close detaches all BPF programs.
func (p *Programs) Close() {
	if p.networkLink != nil {
		p.networkLink.Close()
	}
	if p.execLink != nil {
		p.execLink.Close()
	}
	if p.scrubLink != nil {
		p.scrubLink.Close()
	}
	if p.ExecReader != nil {
		p.ExecReader.Close()
	}
	if p.ScrubReader != nil {
		p.ScrubReader.Close()
	}
}

func populateNetRules(coll *ebpf.Collection, pol *policy.Policy) error {
	allowMap := coll.Maps["allow_rules"]
	denyMap := coll.Maps["deny_rules"]

	for i, r := range pol.Network.Allow {
		rule := netRuleToBytes(r)
		if err := allowMap.Put(uint32(i), rule); err != nil {
			return fmt.Errorf("allow rule %d: %w", i, err)
		}
	}
	for i, r := range pol.Network.Deny {
		rule := netRuleToBytes(r)
		if err := denyMap.Put(uint32(i), rule); err != nil {
			return fmt.Errorf("deny rule %d: %w", i, err)
		}
	}
	return nil
}

type netRuleBytes struct {
	Addr      [4]byte
	Port      uint16
	PrefixLen uint8
	Pad       uint8
}

func netRuleToBytes(r policy.NetworkRule) netRuleBytes {
	var out netRuleBytes
	if r.Host != "" {
		ips, _ := net.LookupIP(r.Host)
		if len(ips) > 0 {
			ip4 := ips[0].To4()
			if ip4 != nil {
				copy(out.Addr[:], ip4)
				out.PrefixLen = 32
			}
		}
	}
	if r.CIDR != "" {
		_, cidr, _ := net.ParseCIDR(r.CIDR)
		if cidr != nil {
			ip4 := cidr.IP.To4()
			if ip4 != nil {
				copy(out.Addr[:], ip4)
				ones, _ := cidr.Mask.Size()
				out.PrefixLen = uint8(ones)
			}
		}
	}
	if r.Port != 0 {
		out.Port = uint16(r.Port)
	}
	if len(r.Ports) > 0 {
		out.Port = uint16(r.Ports[0]) // simplified: first port only in BPF
	}
	return out
}
