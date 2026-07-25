# Session Context for aibpf

## VM Provisioning

- Provider: Linode (Akamai)
- Token: c:\\Users\\andy\\src\\int1\\.env (LINODE_TOKEN=...)
- VM spec: g6-nanode-1, us-east, linode/ubuntu24.04
- SSH key authorized, root password: T3mp!Pwd#2024xZ
- Wait ~90s after creation for boot, SSH as root

## Shell on Windows

- Git Bash: C:\\Program Files\\Git\\bin\\bash.exe
- Invoke: cmd /c C:\\PROGRA~1\\Git\\bin\\bash.exe /path/to/script.sh
- Write .sh scripts first, execute via above (avoids permission loop)
- PowerShell mangles nested quotes - always use .sh scripts

## GitHub

- gh CLI authenticated as acsecengtesting
- Repo: https://github.com/acsecengtesting/aibpf.git
- Local: c:\\Users\\andy\\src\\aibpf
- Push to main

## Kiro Permission Bug

- Bug kirodotdev/Kiro#9507 - Always allow loops on backslash paths
- Workaround: cmd /c C:\\PROGRA~1\\Git\\bin\\bash.exe for shell
- File writes: use shell script if fs_write tool gets permission-looped

## Project: aibpf

eBPF-sandboxed container runtime for AI agents.

### Enforcement layers:
1. Network policy - cgroup/connect4 BPF, allow/deny by host/port/CIDR
2. Secret protection - proxy injects secrets, eBPF scans egress for leaks
3. Exec/filesystem - allowlist binaries, restrict file access

### Design:
- Secret proxy (Go sidecar) outside agent cgroup, replaces {{SECRET:NAME}}
- Agent ONLY reaches internet through proxy (BPF enforced)
- Egress scanning as defense-in-depth
- Declarative YAML policy

### Components to build:
1. Policy schema + parser (Go)
2. Network BPF (cgroup/connect4)
3. Secret scrubbing BPF (socket write scanning)
4. Exec policy BPF (execve allowlist)
5. Secret proxy sidecar (Go)
6. CLI wrapper

## Files created: .gitignore only. Everything else TBD.

## Build pattern: write locally, scp to Linode VM, make, test.
