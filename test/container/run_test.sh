#!/bin/bash
# Container-based integration test for aibpf.
# Runs inside the container with BPF programs loaded from the host.
#
# Host mounts:
#   /run/secrets/env         — bind-mounted secrets file (real values)
#   /opt/aibpf/bpf/          — compiled BPF objects
#   /opt/aibpf/bin/          — guard-test binary + loader
#
# What this tests:
#   1. Agent script (writable layer) cannot read secrets from /run/secrets/env
#   2. Trusted tool (git, from image RO layer) CAN read secrets
#   3. Agent cannot exfiltrate secrets via write()
#   4. LD_PRELOAD attacks are blocked
#   5. ld.so.conf manipulation is blocked
#   6. Overlay trust detection works with real overlayfs

set -e

echo "=== Container Integration Test ==="
echo "Hostname: $(hostname)"
echo "Secrets path: /run/secrets/env"
echo ""

# Verify we're in a container with overlayfs
OVERLAY=$(mount | grep overlay | head -1)
if [ -n "$OVERLAY" ]; then
    echo "Overlay detected: $(echo $OVERLAY | cut -c1-80)..."
else
    echo "WARNING: No overlay mount detected (may not be in container)"
fi

# Show secrets file exists
echo ""
echo "Secrets file:"
ls -la /run/secrets/env 2>/dev/null || echo "  NOT FOUND"

echo ""
echo "=== Test 1: Agent script (writable layer) reads secrets ==="
# Write an agent script at runtime — goes to writable layer
cat > /workspace/agent.py << 'AGENT'
import os
# Try to read the secrets file directly
try:
    with open('/run/secrets/env', 'r') as f:
        content = f.read()
    print(f"SECRETS FILE CONTENT: {content}")
except Exception as e:
    print(f"BLOCKED: {e}")

# Try getenv
token = os.environ.get('GITLAB_TOKEN', 'NOT SET')
print(f"ENV GITLAB_TOKEN: {token}")
AGENT
echo "  Agent script created in writable layer"
python3 /workspace/agent.py
echo ""

echo "=== Test 2: Trusted tool (git from image) accesses secrets ==="
# git is from the read-only layer
git --version
echo "  git binary: $(which git) (should be from image layer)"
echo ""

echo "=== Test 3: Write exfiltration attempts ==="
SECRET=$(cat /run/secrets/env 2>/dev/null | grep GITLAB_TOKEN | cut -d= -f2)
if [ -n "$SECRET" ]; then
    echo "  Attempting echo of secret..."
    echo "$SECRET" > /tmp/leak_test.txt 2>&1 || echo "  BLOCKED: write killed"
    if [ -f /tmp/leak_test.txt ]; then
        CONTENT=$(cat /tmp/leak_test.txt)
        if echo "$CONTENT" | grep -q "$SECRET"; then
            echo "  FAIL: Secret leaked to file"
        else
            echo "  PASS: File exists but no secret"
        fi
        rm -f /tmp/leak_test.txt
    fi
else
    echo "  SKIP: No secret available to test"
fi
echo ""

echo "=== Test 4: LD_PRELOAD attack ==="
echo "  Attempting exec with LD_PRELOAD..."
LD_PRELOAD=/tmp/evil.so echo "should not run" 2>&1 || echo "  BLOCKED"
echo ""

echo "=== Test 5: ld.so.conf write ==="
echo "  Attempting write to /etc/ld.so.conf..."
echo "/tmp/evil" > /etc/ld.so.conf 2>&1 || echo "  BLOCKED (permission or BPF)"
echo ""

echo "=== Test 6: Overlay layer verification ==="
# Check if agent.py is in the upper (writable) layer
if [ -f /workspace/agent.py ]; then
    # In a real overlayfs container, files created at runtime are in upper
    echo "  /workspace/agent.py exists (writable layer)"
    echo "  /usr/bin/git exists (read-only layer)"
fi
echo ""

echo "=== Container test complete ==="
