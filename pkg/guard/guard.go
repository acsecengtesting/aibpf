// Package guard manages the secret_guard BPF program lifecycle.
// It loads the BPF object, populates secret maps, and watches for
// opens to sensitive paths (procfs environ, .env files) to mark fds.
package guard

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	MaxSecretLen = 64
	MaxSecrets   = 16
	PrefixLen    = 8
)

// SecretEntry matches the BPF struct secret_entry layout.
type SecretEntry struct {
	Value [MaxSecretLen]byte
	Len   uint32
}

// Guard holds the loaded BPF programs and maps.
type Guard struct {
	coll        *ebpf.Collection
	writeLink   link.Link
	readEnter   link.Link
	readExit    link.Link
	Events      *perf.Reader
	watchedFds  *ebpf.Map
	secretCount *ebpf.Map
}

// Config defines what to protect.
type Config struct {
	// Secret values to scan for (the actual secret strings)
	Secrets map[string]string // name -> value

	// BPF object file path
	BPFObjectPath string

	// TrustedPIDs: pre-populate trusted process list (optional)
	// In production, overlay_exec.c populates this dynamically
	TrustedPIDs []uint32

	// UntrustedPIDs: pre-populate untrusted process list (optional)
	UntrustedPIDs []uint32
}

// Attach loads the secret_guard BPF and configures it with the given secrets.
func Attach(cfg Config) (*Guard, error) {
	if cfg.BPFObjectPath == "" {
		cfg.BPFObjectPath = "bpf/secret_guard.o"
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObjectPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF object: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("creating BPF collection: %w", err)
	}

	g := &Guard{
		coll:        coll,
		watchedFds:  coll.Maps["watched_fds"],
		secretCount: coll.Maps["secret_count"],
	}

	// Populate secrets map and prefix map
	secretsMap := coll.Maps["secrets"]
	if secretsMap == nil {
		return nil, fmt.Errorf("BPF map 'secrets' not found")
	}
	prefixMap := coll.Maps["secret_prefixes"]
	if prefixMap == nil {
		return nil, fmt.Errorf("BPF map 'secret_prefixes' not found")
	}

	idx := uint32(0)
	for _, val := range cfg.Secrets {
		if idx >= MaxSecrets {
			break
		}
		if len(val) < PrefixLen {
			continue // secret too short to fingerprint
		}
		entry := SecretEntry{Len: uint32(len(val))}
		copy(entry.Value[:], val)
		if err := secretsMap.Put(idx, entry); err != nil {
			return nil, fmt.Errorf("populating secret %d: %w", idx, err)
		}

		// Store prefix for hash lookup
		var prefix [PrefixLen]byte
		copy(prefix[:], val[:PrefixLen])
		if err := prefixMap.Put(prefix, idx); err != nil {
			return nil, fmt.Errorf("populating prefix %d: %w", idx, err)
		}

		idx++
	}

	// Set secret count
	countKey := uint32(0)
	if err := g.secretCount.Put(countKey, idx); err != nil {
		return nil, fmt.Errorf("setting secret count: %w", err)
	}

	// Populate trusted/untrusted PID maps
	trustedMap := coll.Maps["trusted_pids"]
	untrustedMap := coll.Maps["untrusted_pids"]

	if trustedMap != nil {
		for _, pid := range cfg.TrustedPIDs {
			val := uint8(1)
			if err := trustedMap.Put(pid, val); err != nil {
				return nil, fmt.Errorf("adding trusted pid %d: %w", pid, err)
			}
		}
	}
	if untrustedMap != nil {
		for _, pid := range cfg.UntrustedPIDs {
			val := uint8(1)
			if err := untrustedMap.Put(pid, val); err != nil {
				return nil, fmt.Errorf("adding untrusted pid %d: %w", pid, err)
			}
		}
	}

	// Attach tracepoints
	writeProg := coll.Programs["guard_write_enter"]
	if writeProg != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_write", writeProg, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching write tracepoint: %w", err)
		}
		g.writeLink = l
	}

	readEnterProg := coll.Programs["guard_read_enter"]
	if readEnterProg != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_read", readEnterProg, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching read_enter tracepoint: %w", err)
		}
		g.readEnter = l
	}

	readExitProg := coll.Programs["guard_read_exit"]
	if readExitProg != nil {
		l, err := link.Tracepoint("syscalls", "sys_exit_read", readExitProg, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching read_exit tracepoint: %w", err)
		}
		g.readExit = l
	}

	// Set up perf reader for events
	eventsMap := coll.Maps["guard_events"]
	if eventsMap != nil {
		reader, err := perf.NewReader(eventsMap, os.Getpagesize()*8)
		if err != nil {
			return nil, fmt.Errorf("creating perf reader: %w", err)
		}
		g.Events = reader
	}

	return g, nil
}

// WatchFd marks a file descriptor as sensitive for a given pid.
// Reads from this fd will have secrets masked.
func (g *Guard) WatchFd(pid uint32, fd uint32) error {
	key := (uint64(pid) << 32) | uint64(fd)
	val := uint8(1)
	return g.watchedFds.Put(key, val)
}

// MarkUntrusted adds a PID to the untrusted set (writable layer).
func (g *Guard) MarkUntrusted(pid uint32) error {
	untrustedMap := g.coll.Maps["untrusted_pids"]
	if untrustedMap == nil {
		return fmt.Errorf("untrusted_pids map not found")
	}
	val := uint8(1)
	return untrustedMap.Put(pid, val)
}

// MarkTrusted adds a PID to the trusted set (read-only layer).
func (g *Guard) MarkTrusted(pid uint32) error {
	trustedMap := g.coll.Maps["trusted_pids"]
	if trustedMap == nil {
		return fmt.Errorf("trusted_pids map not found")
	}
	val := uint8(1)
	return trustedMap.Put(pid, val)
}

// UnwatchFd removes a watched fd.
func (g *Guard) UnwatchFd(pid uint32, fd uint32) error {
	key := (uint64(pid) << 32) | uint64(fd)
	return g.watchedFds.Delete(key)
}

// Close detaches all BPF programs and frees resources.
func (g *Guard) Close() {
	if g.writeLink != nil {
		g.writeLink.Close()
	}
	if g.readEnter != nil {
		g.readEnter.Close()
	}
	if g.readExit != nil {
		g.readExit.Close()
	}
	if g.Events != nil {
		g.Events.Close()
	}
	if g.coll != nil {
		g.coll.Close()
	}
}

// WatchedPaths are the default paths that should trigger read masking.
func WatchedPaths(pid int) []string {
	return []string{
		fmt.Sprintf("/proc/%d/environ", pid),
		"/proc/self/environ",
		".env",
	}
}

// FindBPFObject locates the secret_guard.o file relative to the binary.
func FindBPFObject() string {
	// Check next to binary
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "..", "bpf", "secret_guard.o"),
		filepath.Join(dir, "bpf", "secret_guard.o"),
		"bpf/secret_guard.o",
		"/opt/aibpf/bpf/secret_guard.o",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "bpf/secret_guard.o"
}

// ParseEvent decodes a raw perf event into a GuardEvent.
type GuardEvent struct {
	PID       uint32
	Action    uint32 // 0=write_blocked, 1=read_masked
	SecretIdx uint32
	FD        uint32
}

func ParseEvent(data []byte) (*GuardEvent, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("event data too short: %d bytes", len(data))
	}
	return &GuardEvent{
		PID:       binary.LittleEndian.Uint32(data[0:4]),
		Action:    binary.LittleEndian.Uint32(data[4:8]),
		SecretIdx: binary.LittleEndian.Uint32(data[8:12]),
		FD:        binary.LittleEndian.Uint32(data[12:16]),
	}, nil
}
