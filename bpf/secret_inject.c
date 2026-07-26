// SPDX-License-Identifier: GPL-2.0
// Secret injection: rewrites {{SECRET:NAME}} placeholders in outbound socket
// writes with real secret values stored in BPF maps.
//
// The agent process NEVER has the real secret in its address space.
// Placeholders get swapped for real values in-kernel via bpf_probe_write_user.
//
// Simplified design to pass BPF verifier:
// - Single linear scan for "{{S" (3-byte prefix signature)
// - Once found, read the full placeholder and extract name
// - Single map lookup, single rewrite
// - One placeholder per write() call (practical limit)

#include "common.h"

#define MAX_SECRET_NAME_LEN 64
#define MAX_SECRET_VAL_LEN 128
#define SCAN_WINDOW 128

// Map: secret name (fixed 64 bytes) -> secret value + length
struct secret_val {
    char value[MAX_SECRET_VAL_LEN];
    __u32 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, char[MAX_SECRET_NAME_LEN]);
    __type(value, struct secret_val);
} secret_map SEC(".maps");

// Per-CPU scratch to avoid stack overflow
struct scratch {
    char buf[SCAN_WINDOW];
    char name[MAX_SECRET_NAME_LEN];
    char replace[MAX_SECRET_VAL_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch);
} scratch_map SEC(".maps");

// Audit event
struct inject_event {
    __u32 pid;
    __u32 fd;
    __u32 offset;
    __u32 placeholder_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} inject_events SEC(".maps");

// Target cgroup (0 = apply to all)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int aibpf_secret_inject(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;

    // Cgroup scoping
    __u64 *target_cg = bpf_map_lookup_elem(&target_cgroup, &zero);
    if (target_cg && *target_cg != 0) {
        if (bpf_get_current_cgroup_id() != *target_cg) return 0;
    }

    int fd = (int)ctx->args[0];
    char *user_buf = (char *)ctx->args[1];
    __u64 count = ctx->args[2];

    // Skip non-socket fds and tiny writes
    if (fd <= 2) return 0;
    if (count < 14) return 0; // {{SECRET:x}} = 13 chars minimum

    struct scratch *s = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!s) return 0;

    // Read first SCAN_WINDOW bytes
    __u64 to_read = count;
    if (to_read > SCAN_WINDOW) to_read = SCAN_WINDOW;
    if (bpf_probe_read_user(s->buf, SCAN_WINDOW, user_buf) < 0) return 0;

    // Linear scan for '{' followed by '{SECRET:'
    // Unrolled: check each position for the 3-byte signature "{{S"
    int found_offset = -1;

    #pragma unroll
    for (int i = 0; i < SCAN_WINDOW - 14; i++) {
        if (s->buf[i] == '{' && s->buf[i+1] == '{' &&
            s->buf[i+2] == 'S' && s->buf[i+3] == 'E' &&
            s->buf[i+4] == 'C' && s->buf[i+5] == 'R' &&
            s->buf[i+6] == 'E' && s->buf[i+7] == 'T' &&
            s->buf[i+8] == ':') {
            found_offset = i;
            break;
        }
    }

    if (found_offset < 0) return 0;

    // Extract secret name: starts at offset+9, ends at "}}"
    __u32 name_start = found_offset + 9;
    __builtin_memset(s->name, 0, MAX_SECRET_NAME_LEN);

    __u32 name_len = 0;
    __u32 placeholder_end = 0;

    #pragma unroll
    for (int j = 0; j < MAX_SECRET_NAME_LEN - 1; j++) {
        __u32 pos = name_start + j;
        if (pos >= SCAN_WINDOW - 1) break;
        if (s->buf[pos] == '}' && s->buf[pos + 1] == '}') {
            placeholder_end = pos + 2;
            break;
        }
        s->name[j] = s->buf[pos];
        name_len++;
    }

    if (placeholder_end == 0 || name_len == 0) return 0;

    // Lookup in secret map
    struct secret_val *secret = bpf_map_lookup_elem(&secret_map, s->name);
    if (!secret || secret->len == 0) return 0;

    // Build replacement: secret value padded with spaces to placeholder length
    __u32 placeholder_len = placeholder_end - found_offset;
    __u32 secret_len = secret->len;
    if (secret_len > MAX_SECRET_VAL_LEN) secret_len = MAX_SECRET_VAL_LEN;

    __builtin_memset(s->replace, ' ', MAX_SECRET_VAL_LEN);
    __builtin_memcpy(s->replace, secret->value, MAX_SECRET_VAL_LEN);

    // Write the secret value over the placeholder in userspace memory
    __u32 write_len = placeholder_len;
    if (write_len > MAX_SECRET_VAL_LEN) write_len = MAX_SECRET_VAL_LEN;

    bpf_probe_write_user(user_buf + found_offset, s->replace, write_len);

    // Audit
    struct inject_event evt = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .fd = (__u32)fd,
        .offset = (__u32)found_offset,
        .placeholder_len = placeholder_len,
    };
    bpf_perf_event_output(ctx, &inject_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
