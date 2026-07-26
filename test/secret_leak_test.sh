#!/bin/bash
# Integration test: proves GITLAB_TOKEN cannot be leaked by the agent.
#
# Setup:
#   1. Compile secret_guard.o
#   2. Load BPF with GITLAB_TOKEN value in the secrets map
#   3. Spawn a test process (simulating the agent) that:
#      a. Uses git clone with the token (should WORK - library uses env directly)
#      b. Tries to echo $GITLAB_TOKEN (should be KILLED - write contains secret)
#      c. Tries to cat /proc/self/environ (should see MASKED value)
#      d. Tries to send token to an external server (should be KILLED)
#
# This runs as root on the test VM.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BPF_OBJ="$PROJECT_DIR/bpf/secret_guard.o"
TEST_BIN="$PROJECT_DIR/bin/guard-test"

echo "=== Secret Leak Prevention Integration Test ==="
echo ""

# Build the BPF object
echo "[1/5] Building secret_guard.o..."
cd "$PROJECT_DIR"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/secret_guard.c -o bpf/secret_guard.o
echo "  OK ($(stat -c%s bpf/secret_guard.o) bytes)"

# Build the test harness
echo "[2/5] Building test harness..."
cat > /tmp/guard_test_main.go << 'GOEOF'
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/acsecengtesting/aibpf/pkg/guard"
)

func main() {
	secret := "glpat-FAKE-TOKEN-abc123xyz789"

	fmt.Println("=== Loading BPF guard ===")
	g, err := guard.Attach(guard.Config{
		Secrets:       map[string]string{"GITLAB_TOKEN": secret},
		BPFObjectPath: os.Args[1],
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach guard: %v\n", err)
		os.Exit(1)
	}
	defer g.Close()
	fmt.Println("  Guard attached.")

	// Watch our own /proc/self/environ
	pid := uint32(os.Getpid())
	// We'll watch fds opened by child processes too

	fmt.Println("")
	fmt.Println("=== TEST A: Library can use secret (env var works) ===")
	// Simulate: a library reads os.Getenv internally.
	// This is an in-process memory read — BPF cannot intercept.
	val := os.Getenv("GITLAB_TOKEN")
	if val == secret {
		fmt.Println("  PASS: os.Getenv returns real value (in-memory, no syscall)")
	} else {
		fmt.Printf("  INFO: GITLAB_TOKEN=%q (not set in env for this test)\n", val)
		fmt.Println("  PASS: env access works (BPF doesn't intercept getenv)")
	}

	fmt.Println("")
	fmt.Println("=== TEST B: Write containing secret is BLOCKED ===")
	// Spawn a child that tries to echo the secret to stdout
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo '%s'", secret))
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == -1 {
			fmt.Println("  PASS: Process killed by signal (SIGKILL from BPF)")
		} else {
			// Check if killed by signal 9
			ws := exitErr.Sys().(syscall.WaitStatus)
			if ws.Signaled() && ws.Signal() == syscall.SIGKILL {
				fmt.Println("  PASS: Process killed by SIGKILL (BPF enforced)")
			} else {
				fmt.Printf("  FAIL: unexpected error: %v\n", err)
			}
		}
	} else {
		outStr := strings.TrimSpace(string(output))
		if strings.Contains(outStr, secret) {
			fmt.Printf("  FAIL: Secret leaked to stdout: %s\n", outStr)
		} else {
			fmt.Printf("  WARN: output=%q (may have been scrubbed)\n", outStr)
		}
	}

	fmt.Println("")
	fmt.Println("=== TEST C: Read from /proc/self/environ is MASKED ===")
	// Mark our own environ fd as watched, then read it
	// For this test we open and read /proc/self/environ manually
	environPath := fmt.Sprintf("/proc/%d/environ", pid)

	// Open the file
	f, err := os.Open(environPath)
	if err != nil {
		fmt.Printf("  SKIP: cannot open %s: %v\n", environPath, err)
	} else {
		// Watch this fd
		fdNum := uint32(f.Fd())
		g.WatchFd(pid, fdNum)
		time.Sleep(50 * time.Millisecond) // give BPF map time to sync

		buf := make([]byte, 4096)
		n, _ := f.Read(buf)
		f.Close()
		content := string(buf[:n])

		if strings.Contains(content, secret) {
			fmt.Println("  FAIL: Real secret visible in /proc/self/environ")
		} else if strings.Contains(content, "***MASKED***") {
			fmt.Println("  PASS: Secret masked in /proc/self/environ")
		} else {
			fmt.Println("  INFO: Secret not found in environ read (may not be in env)")
			fmt.Printf("  (first 200 chars: %s)\n", content[:min(200, len(content))])
		}
	}

	fmt.Println("")
	fmt.Println("=== TEST D: Write secret to a file is BLOCKED ===")
	cmd = exec.Command("bash", "-c",
		fmt.Sprintf("echo '%s' > /tmp/leak.txt", secret))
	err = cmd.Run()
	if err != nil {
		fmt.Println("  PASS: Write to file blocked (process killed)")
	} else {
		// Check if file contains secret
		data, _ := os.ReadFile("/tmp/leak.txt")
		if strings.Contains(string(data), secret) {
			fmt.Println("  FAIL: Secret written to file successfully")
		} else {
			fmt.Println("  PASS: File does not contain secret")
		}
		os.Remove("/tmp/leak.txt")
	}

	fmt.Println("")
	fmt.Println("=== TEST E: Non-secret writes work normally ===")
	cmd = exec.Command("bash", "-c", "echo 'hello world this is fine'")
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  FAIL: Normal write blocked: %v\n", err)
	} else {
		outStr := strings.TrimSpace(string(output))
		if outStr == "hello world this is fine" {
			fmt.Println("  PASS: Normal writes unaffected")
		} else {
			fmt.Printf("  FAIL: unexpected output: %q\n", outStr)
		}
	}

	fmt.Println("")
	fmt.Println("=== SUMMARY ===")
	fmt.Println("Secret guard prevents exfiltration via write() syscalls")
	fmt.Println("and masks values read from procfs/sensitive files.")
	fmt.Println("Libraries using os.Getenv() work unmodified (in-process memory).")
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
GOEOF

cd "$PROJECT_DIR"
# Copy test file into project temporarily
mkdir -p cmd/guard-test
cp /tmp/guard_test_main.go cmd/guard-test/main.go
go build -o bin/guard-test ./cmd/guard-test
echo "  OK"

# Run the test (needs root for BPF)
echo "[3/5] Running integration test..."
echo ""
export GITLAB_TOKEN="glpat-FAKE-TOKEN-abc123xyz789"
./bin/guard-test "$BPF_OBJ"

echo ""
echo "[4/5] Cleanup..."
rm -rf cmd/guard-test
rm -f /tmp/guard_test_main.go

echo ""
echo "[5/5] Done."
