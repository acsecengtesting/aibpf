// SPDX-License-Identifier: GPL-2.0
// Comprehensive environment and linker hardening.
//
// Blocks dangerous environment variables at execve time:
//   - Linker injection: LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT
//   - Python hijack: PYTHONPATH, PYTHONSTARTUP, PYTHONHOME, PYTHONUSERBASE
//   - Node hijack: NODE_PATH, NODE_OPTIONS, NODE_EXTRA_CA_CERTS
//   - Git debug: GIT_TRACE*, GIT_CURL_VERBOSE
//   - TLS MITM: SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE
//   - Proxy hijack: HTTP_PROXY, HTTPS_PROXY, ALL_PROXY
//
// Also blocks write-opens to ld.so config files (ld.so.conf, ld.so.preload).

#include "common.h"

#define MAX_ENV_SCAN 20
#define ENV_VAR_LEN 16
#define MAX_PATH_LEN 64

struct preload_event {
    __u32 pid;
    __u8  reason;  // 0=linker, 1=python, 2=ldconf, 3=debug, 4=tls, 5=proxy, 6=node
    char  detail[ENV_VAR_LEN];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} preload_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} preload_config SEC(".maps");

// Helper: emit event and kill
static __always_inline void kill_with_event(void *ctx, char *buf, __u8 reason) {
    struct preload_event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.reason = reason;
    bpf_get_current_comm(evt.comm, sizeof(evt.comm));
    #pragma unroll
    for (int k = 0; k < ENV_VAR_LEN; k++)
        evt.detail[k] = buf[k];
    bpf_perf_event_output(ctx, &preload_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    bpf_send_signal(9);
}

// ============================================================
// 1. Block dangerous env vars at execve
// ============================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int block_dangerous_env(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&preload_config, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    unsigned long *envp_ptr = (unsigned long *)ctx->args[2];
    if (!envp_ptr)
        return 0;

    #pragma unroll
    for (int i = 0; i < MAX_ENV_SCAN; i++) {
        unsigned long env_entry = 0;
        if (bpf_probe_read_user(&env_entry, sizeof(env_entry), &envp_ptr[i]) < 0)
            break;
        if (env_entry == 0)
            break;

        char buf[ENV_VAR_LEN] = {};
        if (bpf_probe_read_user_str(buf, sizeof(buf), (void *)env_entry) < 0)
            continue;

        // === LINKER: LD_P(reload), LD_L(ibrary), LD_A(udit) ===
        if (buf[0] == 'L' && buf[1] == 'D' && buf[2] == '_') {
            if (buf[3] == 'P' || buf[3] == 'L' || buf[3] == 'A') {
                kill_with_event(ctx, buf, 0);
                return 0;
            }
        }

        // === PYTHON: PYTHON(PATH|STARTUP|HOME|USERBASE) ===
        if (buf[0] == 'P' && buf[1] == 'Y' && buf[2] == 'T' &&
            buf[3] == 'H' && buf[4] == 'O' && buf[5] == 'N') {
            // PYTHONPATH=, PYTHONSTARTUP=, PYTHONHOME=, PYTHONUSERBASE=
            if (buf[6] == 'P' || buf[6] == 'S' || buf[6] == 'H' || buf[6] == 'U') {
                kill_with_event(ctx, buf, 1);
                return 0;
            }
        }

        // === NODE: NODE_P(ath), NODE_O(ptions), NODE_E(xtra_ca) ===
        if (buf[0] == 'N' && buf[1] == 'O' && buf[2] == 'D' &&
            buf[3] == 'E' && buf[4] == '_') {
            if (buf[5] == 'P' || buf[5] == 'O' || buf[5] == 'E') {
                kill_with_event(ctx, buf, 6);
                return 0;
            }
        }

        // === GIT DEBUG: GIT_T(race), GIT_C(url_verbose) ===
        if (buf[0] == 'G' && buf[1] == 'I' && buf[2] == 'T' && buf[3] == '_') {
            if (buf[4] == 'T' || buf[4] == 'C') {
                kill_with_event(ctx, buf, 3);
                return 0;
            }
        }

        // === TLS MITM: SSL_C(ert), REQUESTS_C(a), CURL_CA ===
        if (buf[0] == 'S' && buf[1] == 'S' && buf[2] == 'L' && buf[3] == '_' && buf[4] == 'C') {
            kill_with_event(ctx, buf, 4);
            return 0;
        }
        if (buf[0] == 'R' && buf[1] == 'E' && buf[2] == 'Q' && buf[3] == 'U') {
            // REQUESTS_CA_BUNDLE
            kill_with_event(ctx, buf, 4);
            return 0;
        }
        if (buf[0] == 'C' && buf[1] == 'U' && buf[2] == 'R' && buf[3] == 'L' && buf[4] == '_') {
            // CURL_CA_BUNDLE or CURL_VERBOSE
            kill_with_event(ctx, buf, 4);
            return 0;
        }

        // === PROXY HIJACK: HTTP_P(roxy), HTTPS_P(roxy), ALL_P(roxy) ===
        if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
            // HTTP_PROXY or HTTPS_PROXY
            if (buf[4] == '_' && buf[5] == 'P') {
                kill_with_event(ctx, buf, 5);
                return 0;
            }
            if (buf[4] == 'S' && buf[5] == '_' && buf[6] == 'P') {
                kill_with_event(ctx, buf, 5);
                return 0;
            }
        }
        if (buf[0] == 'A' && buf[1] == 'L' && buf[2] == 'L' && buf[3] == '_' && buf[4] == 'P') {
            kill_with_event(ctx, buf, 5);
            return 0;
        }
    }

    return 0;
}

// ============================================================
// 2. Block write-opens to ld.so config files
// ============================================================

static __always_inline int is_ldso_path(char *path) {
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
        if (path[i] == 0) break;
        if (path[i] == 'l' && path[i+1] == 'd' && path[i+2] == '.' &&
            path[i+3] == 's' && path[i+4] == 'o' && path[i+5] == '.') {
            return 1;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int block_ldconf_open(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&preload_config, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    char *pathname = (char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    if (!(flags & 0x01) && !(flags & 0x02) && !(flags & 0x40))
        return 0;

    if (!pathname)
        return 0;

    char path[MAX_PATH_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    if (is_ldso_path(path)) {
        kill_with_event(ctx, path, 2);
        return 0;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
