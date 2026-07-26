// SPDX-License-Identifier: GPL-2.0
// Secret scrubbing: scans outbound socket writes for secret values.
// Defense-in-depth: even if agent somehow gets a secret value,
// this blocks it from leaving via network.

#include "common.h"

#define MAX_SECRET_LEN 64
#define MAX_SECRETS 32
#define SCAN_BUF_LEN 256

// Secret values to scan for (populated by userspace)
struct secret_entry {
    char value[MAX_SECRET_LEN];
    __u32 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SECRETS);
    __type(key, __u32);
    __type(value, struct secret_entry);
} secret_values SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} secret_count SEC(".maps");

// Per-CPU scratch buffer (avoids stack overflow)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[SCAN_BUF_LEN]);
} scratch_buf SEC(".maps");

// Alert event
struct scrub_event {
    __u32 pid;
    __u32 secret_idx;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} scrub_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int aibpf_scrub_write(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u32 *count = bpf_map_lookup_elem(&secret_count, &zero);
    if (!count || *count == 0) return 0;

    int fd = (int)ctx->args[0];
    char *buf_ptr = (char *)ctx->args[1];
    __u64 buf_len = ctx->args[2];

    // Only scan network-related fds (heuristic: fd > 2)
    if (fd <= 2) return 0;

    // Get per-CPU scratch buffer
    char *buf = bpf_map_lookup_elem(&scratch_buf, &zero);
    if (!buf) return 0;

    // Read up to SCAN_BUF_LEN bytes from the write buffer
    __u64 to_read = buf_len < SCAN_BUF_LEN ? buf_len : SCAN_BUF_LEN;
    if (bpf_probe_read_user(buf, to_read & (SCAN_BUF_LEN - 1), buf_ptr) < 0) return 0;

    __u32 num = *count;
    if (num > MAX_SECRETS) num = MAX_SECRETS;

    // Scan for each secret
    for (__u32 i = 0; i < num && i < MAX_SECRETS; i++) {
        __u32 key = i;
        struct secret_entry *s = bpf_map_lookup_elem(&secret_values, &key);
        if (!s || s->len == 0) continue;

        __u32 slen = s->len;
        if (slen > MAX_SECRET_LEN) slen = MAX_SECRET_LEN;
        if (slen == 0) continue;

        // Simple substring scan (bounded loop)
        __u32 scan_end = (SCAN_BUF_LEN > slen) ? (SCAN_BUF_LEN - slen) : 0;
        for (__u32 j = 0; j < scan_end && j < 192; j++) {
            int match = 1;
            for (__u32 k = 0; k < slen && k < MAX_SECRET_LEN; k++) {
                if (buf[j + k] != s->value[k]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                struct scrub_event evt = {
                    .pid = bpf_get_current_pid_tgid() >> 32,
                    .secret_idx = i,
                    .fd = fd,
                };
                bpf_perf_event_output(ctx, &scrub_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                bpf_send_signal(9);
                return 0;
            }
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
