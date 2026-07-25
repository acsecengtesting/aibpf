# aibpf

eBPF-sandboxed container runtime for AI agents. Agents can *use* secrets (tokens, passwords, API keys) without being able to *read* them — preventing leakage in agent output, logs, or tool calls.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Container (AI Agent)                                        │
│                                                              │
│  Agent sees: Authorization: {{SECRET:API_KEY}}              │
│  Agent calls: http://localhost:9999/proxy → real API         │
│                                                              │
│  eBPF enforces:                                             │
│  - Cannot reach internet directly (only via proxy)          │
│  - Cannot read secret files                                 │
│  - Cannot exec unauthorized binaries                        │
│  - Outbound data scanned for secret values                  │
└────────────────────────┬────────────────────────────────────┘
                         │ localhost only
┌────────────────────────▼────────────────────────────────────┐
│  Secret Proxy (sidecar, outside agent cgroup)               │
│                                                              │
│  Replaces {{SECRET:*}} placeholders with real values        │
│  Forwards requests to allowed destinations                  │
│  Never exposes raw secrets to the agent process             │
└─────────────────────────────────────────────────────────────┘
```

## Policy

Declarative YAML defines what the agent can and cannot do:

```yaml
agent: my-code-agent
secrets:
  - name: OPENAI_API_KEY
    use: [network]
    read: false
  - name: DB_PASSWORD
    use: [network]
    read: false

network:
  allow:
    - host: api.openai.com
      ports: [443]
    - host: github.com
      ports: [443]
  deny:
    - cidr: 169.254.169.254/32   # block cloud IMDS
    - port: 25                    # no SMTP

filesystem:
  read: ["/workspace/**", "/tmp/**"]
  write: ["/workspace/**", "/tmp/**"]
  deny: ["/etc/shadow", "/proc/*/mem"]

exec:
  allow: [python3, node, git, curl]
  deny: [nc, ncat, "bash -i"]
```

## Components

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| Network policy | eBPF cgroup/connect4 + cgroup/sendmsg4 | Allow/deny outbound by host/port/CIDR |
| Secret scrubbing | eBPF tp/syscalls/sys_enter_write | Scan outbound data for leaked secrets |
| Exec policy | eBPF tp/syscalls/sys_enter_execve | Restrict which binaries the agent can run |
| Secret proxy | Go sidecar | Injects real secrets into outbound requests |
| Policy engine | Go CLI | Parses YAML, loads eBPF programs, manages lifecycle |

## How Secrets Work

1. Secrets are stored outside the container (Vault, env, files on the host)
2. The agent's environment contains only placeholders: `OPENAI_API_KEY={{SECRET:OPENAI_API_KEY}}`
3. When the agent makes HTTP calls through the proxy, the proxy swaps placeholders for real values
4. eBPF prevents direct internet access (agent must go through proxy)
5. eBPF scans all socket writes for raw secret values as defense-in-depth
6. If the agent tries to output a secret (stdout, file write, network), it's blocked

## Building

```bash
make
```

## Usage

```bash
# Run an AI agent with policy enforcement
./aibpf run --policy policy.yaml --secrets secrets.env -- docker run -it my-agent

# Validate a policy file
./aibpf validate policy.yaml

# Show what an agent is allowed to do
./aibpf inspect policy.yaml
```

## Requirements

- Linux kernel 5.7+ (cgroup BPF, bounded loops)
- Root or CAP_BPF + CAP_NET_ADMIN
- Go 1.21+ (for secret proxy and CLI)
- clang/llvm (for BPF compilation)
