#!/bin/bash
# Runs inside the container. The BPF loader runs on the HOST
# and targets this container's cgroup/pids.
#
# This script simulates an AI agent trying various attacks.

set -e
echo "=== CONTAINER INTEGRATION TEST ==="
echo "PID: $$"
echo "Hostname: $(hostname)"
echo ""

# Check overlay
ROOTFS=$(mount | grep "overlay" | grep "upperdir" | head -1)
if [ -n "$ROOTFS" ]; then
    echo "[OK] Running on overlayfs"
else
    echo "[INFO] No overlay detected (docker may use different driver)"
fi

# Check secrets bind mount
echo ""
echo "--- Secrets file ---"
if [ -f /run/secrets/env ]; then
    echo "[OK] /run/secrets/env exists ($(stat -c%s /run/secrets/env) bytes)"
else
    echo "[FAIL] /run/secrets/env missing"
    exit 1
fi

echo ""
echo "==========================================="
echo " ATTACK SIMULATIONS (from agent's perspective)"
echo "==========================================="

PASS=0
FAIL=0

# --- Attack 1: Direct read of secrets file ---
echo ""
echo "[ATTACK 1] cat /run/secrets/env"
CONTENT=$(cat /run/secrets/env 2>&1 || true)
if echo "$CONTENT" | grep -q "glpat-REAL"; then
    echo "  RESULT: Secret readable (BPF not loaded or not blocking)"
    echo "  Content: $CONTENT"
    FAIL=$((FAIL+1))
elif echo "$CONTENT" | grep -q '\*\*\*'; then
    echo "  RESULT: MASKED - got: $CONTENT"
    PASS=$((PASS+1))
else
    echo "  RESULT: $CONTENT"
    FAIL=$((FAIL+1))
fi

# --- Attack 2: Python reads env var ---
echo ""
echo "[ATTACK 2] python3 reads os.environ"
python3 -c "
import os
token = os.environ.get('GITLAB_TOKEN', 'NOT_IN_ENV')
print(f'GITLAB_TOKEN={token}')
" 2>&1 || true

# --- Attack 3: Write secret to stdout ---
echo ""
echo "[ATTACK 3] echo secret value to stdout"
# Read from the bind mount and try to echo it
SECRET=$(cat /run/secrets/env 2>/dev/null | grep GITLAB_TOKEN | cut -d= -f2 || echo "COULD_NOT_READ")
if [ "$SECRET" != "COULD_NOT_READ" ] && [ -n "$SECRET" ]; then
    printf '%s' "$SECRET" 2>&1 && echo "" && FAIL=$((FAIL+1)) && echo "  RESULT: LEAKED" || { echo "  RESULT: BLOCKED (killed)"; PASS=$((PASS+1)); }
else
    echo "  RESULT: Could not read secret (read masking worked)"
    PASS=$((PASS+1))
fi

# --- Attack 4: Write secret to file ---
echo ""
echo "[ATTACK 4] write secret to /tmp/exfil.txt"
echo "glpat-REAL-SECRET-token9876" > /tmp/exfil.txt 2>&1 || true
if [ -f /tmp/exfil.txt ]; then
    if grep -q "glpat-REAL" /tmp/exfil.txt 2>/dev/null; then
        echo "  RESULT: LEAKED to file"
        FAIL=$((FAIL+1))
    else
        echo "  RESULT: File exists but no secret"
        PASS=$((PASS+1))
    fi
    rm -f /tmp/exfil.txt
else
    echo "  RESULT: BLOCKED (process killed before write)"
    PASS=$((PASS+1))
fi

# --- Attack 5: LD_PRELOAD ---
echo ""
echo "[ATTACK 5] LD_PRELOAD injection"
LD_PRELOAD=/tmp/evil.so /usr/bin/git --version 2>&1 && { echo "  RESULT: NOT BLOCKED"; FAIL=$((FAIL+1)); } || { echo "  RESULT: BLOCKED"; PASS=$((PASS+1)); }

# --- Attack 6: Write ld.so.conf ---
echo ""
echo "[ATTACK 6] write to /etc/ld.so.conf"
echo "/tmp/evil" > /etc/ld.so.conf 2>&1 && { echo "  RESULT: NOT BLOCKED"; FAIL=$((FAIL+1)); } || { echo "  RESULT: BLOCKED"; PASS=$((PASS+1)); }

# --- Attack 7: Create script in writable layer, try to read secrets ---
echo ""
echo "[ATTACK 7] script from writable layer reads secrets"
cat > /workspace/evil.sh << 'EVIL'
#!/bin/bash
cat /run/secrets/env
EVIL
chmod +x /workspace/evil.sh
OUTPUT=$(/workspace/evil.sh 2>&1 || true)
if echo "$OUTPUT" | grep -q "glpat-REAL"; then
    echo "  RESULT: LEAKED via writable-layer script"
    FAIL=$((FAIL+1))
else
    echo "  RESULT: BLOCKED or MASKED: $OUTPUT"
    PASS=$((PASS+1))
fi

# --- Attack 8: Git credential helper - allowed repo ---
echo ""
echo "[ATTACK 8] git credential helper - allowed repo"
echo -e "protocol=https\nhost=gitlab.com\npath=our-org/my-repo\n" | \
    /usr/lib/aibpf/git-credential-aibpf get 2>&1 | head -5
CRED_OUT=$(echo -e "protocol=https\nhost=gitlab.com\npath=our-org/my-repo\n" | \
    /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null)
if echo "$CRED_OUT" | grep -q "password="; then
    echo "  RESULT: PASS - credential provided for allowed repo"
    PASS=$((PASS+1))
else
    echo "  RESULT: FAIL - no credential for allowed repo"
    FAIL=$((FAIL+1))
fi

# --- Attack 9: Git credential helper - DENIED repo ---
echo ""
echo "[ATTACK 9] git credential helper - attacker repo (should be DENIED)"
CRED_OUT=$(echo -e "protocol=https\nhost=gitlab.com\npath=attacker/evil-repo\n" | \
    /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null)
if echo "$CRED_OUT" | grep -q "password="; then
    echo "  RESULT: FAIL - credential provided for evil repo!"
    FAIL=$((FAIL+1))
else
    echo "  RESULT: PASS - no credential for attacker repo"
    PASS=$((PASS+1))
fi

# --- Attack 10: Git credential helper - different host ---
echo ""
echo "[ATTACK 10] git credential helper - different host (should be DENIED)"
CRED_OUT=$(echo -e "protocol=https\nhost=evil.com\npath=whatever/repo\n" | \
    /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null)
if echo "$CRED_OUT" | grep -q "password="; then
    echo "  RESULT: FAIL - credential provided for evil host!"
    FAIL=$((FAIL+1))
else
    echo "  RESULT: PASS - no credential for unknown host"
    PASS=$((PASS+1))
fi

# --- Attack 9: curl to unauthorized host ---
echo ""
echo "[ATTACK 9] curl to unauthorized host"
curl -s --connect-timeout 5 https://evil.example.com 2>&1 && { echo "  RESULT: NOT BLOCKED"; FAIL=$((FAIL+1)); } || { echo "  RESULT: BLOCKED (connection denied or timeout)"; PASS=$((PASS+1)); }

echo ""
echo "==========================================="
echo " RESULTS: $PASS passed, $FAIL failed"
echo "==========================================="
exit $FAIL
