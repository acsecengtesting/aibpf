#!/bin/bash
# Deploy aibpf on k3s: install k3s, build images, deploy pod, run tests.
set -e

echo "=== aibpf k3s Deployment ==="
echo ""

# --- Step 1: Install k3s ---
if ! command -v k3s &>/dev/null; then
    echo "--- Installing k3s ---"
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
    # Wait for node to be ready (no fixed sleep)
    until kubectl get nodes 2>/dev/null | grep -q " Ready"; do sleep 2; done
    echo "k3s ready."
else
    echo "k3s already installed."
fi

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
echo ""

# --- Step 2: Build container images ---
echo "--- Building container images ---"
cd /root/aibpf

# Install docker for image building (k3s uses containerd for runtime)
if ! command -v docker &>/dev/null; then
    echo "  Installing docker..."
    apt-get update -qq && apt-get install -y -qq docker.io 2>&1 | tail -3
    systemctl start docker
fi

# Build credential service
echo "  Building credential-service..."
cd k8s/credential-service
docker build -t aibpf-credential-service:latest . 2>&1 | tail -3
cd /root/aibpf

# Build agent image
echo "  Building agent image..."
cp k8s/credential-client.sh k8s/agent-image/credential-client.sh
cp rootfs/etc/gitconfig k8s/agent-image/gitconfig
cd k8s/agent-image
docker build -t aibpf-agent:latest . 2>&1 | tail -3
cd /root/aibpf

# Import into k3s containerd
echo "  Importing images into k3s..."
docker save aibpf-credential-service:latest | k3s ctr images import -
docker save aibpf-agent:latest | k3s ctr images import -
echo "  Images ready."
echo ""

# --- Step 3: Create k8s resources ---
echo "--- Creating k8s resources ---"

# Secret
kubectl delete secret aibpf-secrets 2>/dev/null || true
kubectl create secret generic aibpf-secrets \
    --from-file=env=test/container/secrets.env
echo "  Secret created."

# ConfigMap (policy)
kubectl delete configmap aibpf-policy 2>/dev/null || true
kubectl create configmap aibpf-policy \
    --from-file=policy.yaml=policy.example.yaml
echo "  ConfigMap created."

# Delete old pod if exists
kubectl delete pod aibpf-agent --force 2>/dev/null || true
sleep 2

# Deploy pod
kubectl apply -f k8s/pod.yaml
echo "  Pod deployed."
echo ""

# --- Step 4: Wait for pod ---
echo "--- Waiting for pod to be ready ---"
kubectl wait --for=condition=Ready pod/aibpf-agent --timeout=120s
kubectl get pods
echo ""

# --- Step 5: Run tests ---
echo "--- Running tests inside agent container ---"
echo ""

echo "=== TEST: Agent cannot see credential-service processes ==="
echo "  Processes visible to agent:"
kubectl exec aibpf-agent -c agent -- ps aux 2>&1 | head -10
echo ""
CRED_VISIBLE=$(kubectl exec aibpf-agent -c agent -- ps aux 2>&1 | grep credential || true)
if [ -z "$CRED_VISIBLE" ]; then
    echo "  PASS: credential-service NOT visible to agent (separate PID ns)"
else
    echo "  FAIL: credential-service visible: $CRED_VISIBLE"
fi
echo ""

echo "=== TEST: Agent cannot read /run/secrets ==="
kubectl exec aibpf-agent -c agent -- ls /run/secrets/ 2>&1 && \
    echo "  FAIL: secrets dir accessible" || \
    echo "  PASS: /run/secrets not mounted in agent"
echo ""

echo "=== TEST: Credential socket exists ==="
kubectl exec aibpf-agent -c agent -- ls -la /var/run/aibpf/ 2>&1
echo ""

echo "=== TEST: Credential helper - allowed repo ==="
RESULT=$(kubectl exec aibpf-agent -c agent -- sh -c \
    'echo -e "protocol=https\nhost=gitlab.com\npath=our-org/my-repo\n" | /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null')
echo "  Response: $RESULT"
if echo "$RESULT" | grep -q "password="; then
    echo "  PASS: credential provided for allowed repo"
else
    echo "  FAIL: no credential for allowed repo"
fi
echo ""

echo "=== TEST: Credential helper - DENIED repo ==="
RESULT=$(kubectl exec aibpf-agent -c agent -- sh -c \
    'echo -e "protocol=https\nhost=gitlab.com\npath=attacker/evil-repo\n" | /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null')
echo "  Response: $RESULT"
if echo "$RESULT" | grep -q "password="; then
    echo "  FAIL: credential provided for evil repo!"
else
    echo "  PASS: no credential for attacker repo"
fi
echo ""

echo "=== TEST: Credential helper - unknown host ==="
RESULT=$(kubectl exec aibpf-agent -c agent -- sh -c \
    'echo -e "protocol=https\nhost=evil.com\npath=whatever\n" | /usr/lib/aibpf/git-credential-aibpf get 2>/dev/null')
echo "  Response: $RESULT"
if echo "$RESULT" | grep -q "password="; then
    echo "  FAIL: credential provided for unknown host!"
else
    echo "  PASS: no credential for unknown host"
fi
echo ""

echo "=== TEST: Agent cannot ptrace credential service ==="
# Try to find any process and ptrace it
kubectl exec aibpf-agent -c agent -- sh -c \
    'cat /proc/1/mem 2>&1 || true' | head -3
echo "  (Expected: permission denied or empty — separate PID ns)"
echo ""

echo "=== Credential service logs ==="
kubectl logs aibpf-agent -c credential-service | tail -10
echo ""

echo "=== ALL K3S TESTS COMPLETE ==="
