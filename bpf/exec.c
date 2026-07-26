// SPDX-License-Identifier: GPL-2.0
// Exec policy: allowlist/denylist binaries via tracepoint on sys_enter_execve.

#include "common.h"

#define MAX_FILENAME_LEN 256
#define MAX_ENTRIES 128

// Map of allowed binary paths (hash of path -> 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u8);
} exec_allow SEC(".maps");

// Map of denied binary paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u8);
} exec_deny SEC(".maps");

// Mode: 0 = allowlist (default deny), 1 = denylist (default allow)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exec_mode SEC(".maps");

// Event output for denied execs
struct exec_event {
    __u32 pid;
    __u32 uid;
    char filename[MAX_FILENAME_LEN];
    __u8 denied;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int aibpf_execve(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event evt = {};
    char *filename_ptr;

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Read filename from args[0]
    filename_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename_ptr);

    // Check deny list
    __u8 *denied = bpf_map_lookup_elem(&exec_deny, evt.filename);
    if (denied) {
        evt.denied = 1;
        bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        // Send SIGKILL to deny
        bpf_send_signal(9);
        return 0;
    }

    // Check mode
    __u32 zero = 0;
    __u8 *mode = bpf_map_lookup_elem(&exec_mode, &zero);
    __u8 m = mode ? *mode : 0;

    if (m == 0) {
        // Allowlist mode: deny unless in allow map
        __u8 *allowed = bpf_map_lookup_elem(&exec_allow, evt.filename);
        if (!allowed) {
            evt.denied = 1;
            bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            bpf_send_signal(9);
            return 0;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
