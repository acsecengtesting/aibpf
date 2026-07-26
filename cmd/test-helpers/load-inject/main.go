// load-inject: loads the secret_inject BPF program and populates secret maps.
// Used in integration tests. Stays running while tests execute.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	MaxSecretNameLen = 64
	MaxSecretValLen  = 128
)

type secretVal struct {
	Value [MaxSecretValLen]byte
	Len   uint32
}

func main() {
	bpfObj := flag.String("obj", "bpf/secret_inject.o", "path to BPF object file")
	secrets := flag.String("secrets", "", "comma-separated NAME=VALUE pairs")
	flag.Parse()

	if *secrets == "" {
		log.Fatal("-secrets is required (e.g. GITLAB_TOKEN=glpat-xxx)")
	}

	// Load BPF
	spec, err := ebpf.LoadCollectionSpec(*bpfObj)
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	// Populate secret map
	secretMap := coll.Maps["secret_map"]
	if secretMap == nil {
		log.Fatal("secret_map not found in BPF object")
	}

	for _, pair := range strings.Split(*secrets, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			log.Fatalf("invalid secret pair: %q", pair)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		key := make([]byte, MaxSecretNameLen)
		copy(key, k)

		val := secretVal{Len: uint32(len(v))}
		copy(val.Value[:], v)

		if err := secretMap.Put(key, val); err != nil {
			log.Fatalf("putting secret %q: %v", k, err)
		}
		fmt.Printf("Loaded secret: %s (%d bytes)\n", k, len(v))
	}

	// Attach tracepoint
	injectProg := coll.Programs["aibpf_secret_inject"]
	if injectProg == nil {
		log.Fatal("program aibpf_secret_inject not found")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_write", injectProg, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("BPF secret_inject attached to syscalls/sys_enter_write")
	fmt.Println("Secrets will be injected for {{SECRET:NAME}} placeholders")
	fmt.Println("Press Ctrl+C to detach and exit")

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\nDetaching...")
}
