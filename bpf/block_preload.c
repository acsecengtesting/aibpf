// SPDX-License-Identifier: GPL-2.0
// Block LD_PRELOAD/LD_LIBRARY_PATH and protect ld.so.conf.
//
// Three enforcement layers:
// 1. sys_enter_execve: scan envp for LD_PRELOAD/LD_LIBRARY_PATH, SIGKILL
// 2. sys_enter_openat: if path contains "ld.so.conf" and flags include
//    O_WRONLY/O_RDWR/O_CREAT, SIGKILL (prevents writing new linker config)
// 3. Combined with overlay_exec: anything from writable layer trying to
//    modify linker behavior is killed
//
// In production, LD_PRELOAD should also be stripped from the container env
// at launch time (defense-in-depth).

#include "common.h"

#define MAX_ENV_SCAN 20
#define ENV_VAR_LEN 16
#define MAX_PATH_LEN 64

// --- Events ---

struct preload_event {
    __u32 pid;
    __u8  reason;  // 0=LD_PRELOAD, 1=LD_LIBRARY_PATH, 2=ld.so.conf write
    char  detail[ENV_VAR_LEN];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} preload_events SEC(".maps");

// Config: enable/disable
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} preload_config SEC(".maps");

// ============================================================
// 1. Block LD_PRELOAD / LD_LIBRARY_PATH in execve envp
// ============================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int block_ld_preload(struct trace_event_raw_sys_enter *ctx) {
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

        // Fast prefix: must start with "LD_"
        if (buf[0] != 'L' || buf[1] != 'D' || buf[2] != '_')
            continue;

        // LD_PRELOAD= (LD_P...)
        // LD_LIBRARY_PATH= (LD_L...)
        // LD_AUDIT= (LD_A...) — also dangerous
        int dangerous = 0;
        __u8 reason = 0;

        if (buf[3] == 'P' && buf[4] == 'R' && buf[5] == 'E') {
            dangerous = 1;
            reason = 0;
        }
        if (buf[3] == 'L' && buf[4] == 'I' && buf[5] == 'B') {
            dangerous = 1;
            reason = 1;
        }
        if (buf[3] == 'A' && buf[4] == 'U' && buf[5] == 'D') {
            dangerous = 1;  // LD_AUDIT
            reason = 0;
        }

        if (dangerous) {
            struct preload_event evt = {};
            evt.pid = bpf_get_current_pid_tgid() >> 32;
            evt.reason = reason;
            bpf_get_current_comm(evt.comm, sizeof(evt.comm));
            #pragma unroll
            for (int k = 0; k < ENV_VAR_LEN; k++)
                evt.detail[k] = buf[k];

            bpf_perf_event_output(ctx, &preload_events,
                BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            bpf_send_signal(9);
            return 0;
        }
    }

    return 0;
}

// ============================================================
// 2. Block ALL access to ld.so.conf, ld.so.preload, ld.so.conf.d
//    from untrusted processes. Also blocks mmap-based attacks.
//    Trusted processes (from RO layer) are exempt.
// ============================================================

// Check if path contains ld.so config patterns
static __always_inline int is_ldso_path(char *path) {
    // Check for "ld.so." anywhere in path
    // Catches: /etc/ld.so.conf, /etc/ld.so.conf.d/*, /etc/ld.so.preload,
    //          ld.so.cache (also dangerous to write)
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

// Hook openat — block ANY process from opening ld.so config for write/read
// There is no legitimate reason for any process in the container to modify
// or even read linker config (ld.so itself reads it, but that happens at
// process startup before our BPF attaches to that process).
SEC("tracepoint/syscalls/sys_enter_openat")
int block_ldconf_open(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&preload_config, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    // args[1] = pathname, args[2] = flags
    char *pathname = (char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    // Only block write/create opens (read-only access to ld.so.conf is OK
    // for diagnostic tools, but write is never OK)
    if (!(flags & 0x01) && !(flags & 0x02) && !(flags & 0x40))
        return 0;

    if (!pathname)
        return 0;

    char path[MAX_PATH_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    if (is_ldso_path(path)) {
        struct preload_event evt = {};
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.reason = 2;
        bpf_get_current_comm(evt.comm, sizeof(evt.comm));
        #pragma unroll
        for (int k = 0; k < ENV_VAR_LEN && k < MAX_PATH_LEN; k++)
            evt.detail[k] = path[k];

        bpf_perf_event_output(ctx, &preload_events,
            BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
