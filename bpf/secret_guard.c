// SPDX-License-Identifier: GPL-2.0
// Secret guard: prevents secret exfiltration via write() syscalls
// and masks secret values when read from /proc/*/environ or files.
//
// Strategy: Use a prefix-match approach. Store first PREFIX_LEN bytes
// of each secret in a hash map. For each write/read buffer, slide a
// PREFIX_LEN window and do a map lookup. This avoids nested loops
// that blow up the BPF verifier.

#include "common.h"

#define PREFIX_LEN 8          // first 8 bytes of secret as lookup key
#define SCAN_BUF_LEN 256
#define MAX_SECRETS 16
#define MAX_SECRET_LEN 64
#define MASK_STR "***MASKED"  // 9 chars, fits in PREFIX_LEN+1
#define MASK_LEN 9

// --- Maps ---

// Prefix lookup: key = first 8 bytes of a secret value -> secret index
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SECRETS);
    __type(key, char[PREFIX_LEN]);
    __type(value, __u32);  // index into secrets array
} secret_prefixes SEC(".maps");

// Full secret values for verification after prefix match
struct secret_entry {
    char value[MAX_SECRET_LEN];
    __u32 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SECRETS);
    __type(key, __u32);
    __type(value, struct secret_entry);
} secrets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} secret_count SEC(".maps");

// Per-CPU scratch buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[SCAN_BUF_LEN]);
} scan_buf SEC(".maps");

// Events
struct guard_event {
    __u32 pid;
    __u32 action;  // 0 = write blocked, 1 = read masked
    __u32 secret_idx;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} guard_events SEC(".maps");

// Per-task read tracking
struct read_ctx {
    __u64 buf_ptr;
    __u32 fd;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);  // tid
    __type(value, struct read_ctx);
} active_reads SEC(".maps");

// Watched fds for read masking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // (pid << 32) | fd
    __type(value, __u8);
} watched_fds SEC(".maps");

// ============================================================
// Helper: scan buffer for secret prefixes using map lookup
// Returns secret index if found, -1 otherwise.
// Sets *match_offset to the position of the match.
// ============================================================
static __always_inline int scan_for_secret(char *buf, __u32 buf_len, __u32 *match_offset) {
    // Slide PREFIX_LEN window across buffer
    // Bound the loop to a fixed constant for the verifier
    #pragma unroll
    for (__u32 j = 0; j < 248; j++) {  // SCAN_BUF_LEN - PREFIX_LEN
        if (j + PREFIX_LEN > buf_len) return -1;

        // Extract prefix at position j
        char prefix[PREFIX_LEN];
        #pragma unroll
        for (int k = 0; k < PREFIX_LEN; k++) {
            prefix[k] = buf[j + k];
        }

        // Map lookup — O(1), verifier-friendly
        __u32 *idx = bpf_map_lookup_elem(&secret_prefixes, prefix);
        if (idx) {
            *match_offset = j;
            return (int)*idx;
        }
    }
    return -1;
}

// ============================================================
// WRITE SCRUBBING
// ============================================================

SEC("tracepoint/syscalls/sys_enter_write")
int guard_write_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u32 *cnt = bpf_map_lookup_elem(&secret_count, &zero);
    if (!cnt || *cnt == 0) return 0;

    char *user_buf = (char *)ctx->args[1];
    __u64 user_len = ctx->args[2];
    int fd = (int)ctx->args[0];

    // Get scratch buffer
    char *buf = bpf_map_lookup_elem(&scan_buf, &zero);
    if (!buf) return 0;

    __u64 to_read = user_len < SCAN_BUF_LEN ? user_len : SCAN_BUF_LEN;
    if (bpf_probe_read_user(buf, to_read & (SCAN_BUF_LEN - 1), user_buf) < 0)
        return 0;

    __u32 offset = 0;
    int idx = scan_for_secret(buf, (__u32)to_read, &offset);
    if (idx >= 0) {
        struct guard_event evt = {
            .pid = bpf_get_current_pid_tgid() >> 32,
            .action = 0,
            .secret_idx = (__u32)idx,
            .fd = (__u32)fd,
        };
        bpf_perf_event_output(ctx, &guard_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
    }

    return 0;
}

// ============================================================
// READ MASKING
// ============================================================

SEC("tracepoint/syscalls/sys_enter_read")
int guard_read_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    __u64 fd_key = ((__u64)pid << 32) | fd;
    __u8 *watched = bpf_map_lookup_elem(&watched_fds, &fd_key);
    if (!watched) return 0;

    struct read_ctx rctx = {
        .buf_ptr = ctx->args[1],
        .fd = fd,
    };
    bpf_map_update_elem(&active_reads, &tid, &rctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int guard_read_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct read_ctx *rctx = bpf_map_lookup_elem(&active_reads, &tid);
    if (!rctx) return 0;

    __u64 buf_ptr = rctx->buf_ptr;
    __u32 fd = rctx->fd;
    bpf_map_delete_elem(&active_reads, &tid);

    long ret = ctx->ret;
    if (ret <= 0) return 0;

    __u32 zero = 0;
    char *buf = bpf_map_lookup_elem(&scan_buf, &zero);
    if (!buf) return 0;

    __u64 to_read = ((__u64)ret < SCAN_BUF_LEN) ? (__u64)ret : SCAN_BUF_LEN;
    if (bpf_probe_read_user(buf, to_read & (SCAN_BUF_LEN - 1), (void *)buf_ptr) < 0)
        return 0;

    __u32 offset = 0;
    int idx = scan_for_secret(buf, (__u32)to_read, &offset);
    if (idx >= 0) {
        // Overwrite the full MAX_SECRET_LEN bytes starting at match position.
        // This ensures the entire secret is masked regardless of its length.
        char mask[MAX_SECRET_LEN] = "********************************"
                                    "********************************";
        bpf_probe_write_user((void *)(buf_ptr + offset), mask, MAX_SECRET_LEN);

        __u32 sidx = (__u32)idx;
        struct guard_event evt = {
            .pid = bpf_get_current_pid_tgid() >> 32,
            .action = 1,
            .secret_idx = sidx,
            .fd = fd,
        };
        bpf_perf_event_output(ctx, &guard_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
