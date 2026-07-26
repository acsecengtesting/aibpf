#!/bin/bash
# Host-side script: builds container, loads BPF, runs tests.
# Run this on the VM (as root, with docker installed).
set -e

cd /root/aibpf
echo "=== Docker Container Integration Test ==="
echo ""

# --- Step 1: Install docker if needed ---
if ! command -v docker &>/dev/null; then
    echo "--- Installing Docker ---"
    apt-get update -qq
    apt-get install -y -qq docker.io
    systemctl start docker
fi
echo "Docker: $(docker --version)"

# --- Step 2: Build test image ---
echo ""
echo "--- Building test container image ---"
docker build -t aibpf-test -f test/container/Dockerfile test/container/
echo "  Image built."

# --- Step 3: Build BPF and Go binaries (already done by deploy.sh) ---
echo ""
echo "--- Checking BPF objects ---"
ls -la bpf/secret_guard.o bpf/block_preload.o bpf/overlay_exec.o bpf/net_pertool.o

# --- Step 4: Build the container test loader ---
# This Go binary loads BPF, starts the container, and monitors events.
echo ""
echo "--- Building container test loader ---"
mkdir -p cmd/container-test
cat > cmd/container-test/main.go << 'LOADER'
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/acsecengtesting/aibpf/pkg/guard"
)

func main() {
	bpfObj := "bpf/secret_guard.o"
	secretsFile := "test/container/secrets.env"

	// Read secrets from the bind-mount source
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read secrets file: %v\n", err)
		os.Exit(1)
	}

	secrets := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			secrets[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	fmt.Printf("Loaded %d secrets from %s\n", len(secrets), secretsFile)

	// Load BPF guard
	fmt.Println("Loading BPF guard...")
	g, err := guard.Attach(guard.Config{
		Secrets:       secrets,
		BPFObjectPath: bpfObj,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	defer g.Close()
	fmt.Println("BPF guard attached (global — all processes)")
	fmt.Println("")

	// Start the container
	fmt.Println("--- Starting container ---")
	cmd := exec.Command("docker", "run", "--rm",
		"--name", "aibpf-test-run",
		// Bind mount secrets
		"-v", "/root/aibpf/test/container/secrets.env:/run/secrets/env:ro",
		// Bind mount the test script
		"-v", "/root/aibpf/test/container/run_in_container.sh:/opt/run_test.sh:ro",
		// Run as non-root agent user? No, keep root for now.
		"aibpf-test",
		"bash", "/opt/run_test.sh",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start container: %v\n", err)
		os.Exit(1)
	}

	// Get container PID to mark it untrusted
	time.Sleep(1 * time.Second)
	pidOut, _ := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", "aibpf-test-run").Output()
	pidStr := strings.TrimSpace(string(pidOut))
	if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil && pid > 0 {
		fmt.Printf("Container init PID: %d — marking untrusted\n", pid)
		g.MarkUntrusted(uint32(pid))
		// Also mark child PIDs (bash, python, etc.)
		for i := uint32(1); i <= 50; i++ {
			g.MarkUntrusted(uint32(pid) + i)
		}
	}

	// Wait for container to finish
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("\nContainer exited with error: %v\n", err)
	} else {
		fmt.Println("\nContainer test completed successfully.")
	}
}
LOADER

go build -o bin/container-test ./cmd/container-test && echo "  bin/container-test OK"
rm -rf cmd/container-test

# --- Step 5: Run the test ---
echo ""
echo "--- Running container test with BPF guard ---"
echo ""
./bin/container-test

echo ""
echo "=== Docker test complete ==="
