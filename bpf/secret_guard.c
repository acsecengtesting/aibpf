// SPDX-License-Identifier: GPL-2.0
// Secret guard: prevents secret exfiltration via write() syscalls
// and masks secret values when read from .env / secrets files.
//
// Trust model (overlay-aware):
//   - Processes from read-only layer (trusted_pids) → can read secrets freely
//   - Processes from writable layer (untrusted_pids) → writes are scrubbed,
//     reads are masked
//   - If overlay_exec is not loaded, ALL processes are treated as untrusted
//     (fail-safe)
//
// Strategy: Use a prefix-match approach. Store first PREFIX_LEN bytes
// of each secret in a hash map. For each write/read buffer, slide a
// PREFIX_LEN window and do a map lookup.

#include "common.h"

#define PREFIX_LEN 8
#define SCAN_BUF_LEN 256
#define MAX_SECRETS 16
#define MAX_SECRET_LEN 64

// --- Shared maps (pinned, shared with overlay_exec.c) ---

// Untrusted PIDs: processes running from writable layer
// Populated by overlay_exec.c, read by this program
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} untrusted_pids SEC(".maps");

// Trusted PIDs: processes running from read-only layer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} trusted_pids SEC(".maps");

// --- Secret storage ---

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SECRETS);
    __type(key, char[PREFIX_LEN]);
    __type(value, __u32);
} secret_prefixes SEC(".maps");

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
    __u32 action;  // 0 = write blocked, 1 = read masked, 2 = trusted (audit)
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
    __type(key, __u32);
    __type(value, struct read_ctx);
} active_reads SEC(".maps");

// Watched fds for read masking (auto-populated on openat of secrets files)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // (pid << 32) | fd
    __type(value, __u8);
} watched_fds SEC(".maps");

// ============================================================
// Helper: check if current process is trusted (from RO layer)
// Returns 1 if trusted, 0 if untrusted or unknown
// ============================================================
static __always_inline int is_trusted_pid(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted)
        return 1;
    return 0;
}

// ============================================================
// Helper: scan buffer for secret prefixes using map lookup
// ============================================================
static __always_inline int scan_for_secret(char *buf, __u32 buf_len, __u32 *match_offset) {
    #pragma unroll
    for (__u32 j = 0; j < 248; j++) {
        if (j + PREFIX_LEN > buf_len) return -1;

        char prefix[PREFIX_LEN];
        #pragma unroll
        for (int k = 0; k < PREFIX_LEN; k++) {
            prefix[k] = buf[j + k];
        }

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
// - fd 0/1/2 (stdin/stdout/stderr): ALWAYS scrub, even trusted processes
//   (prevents debug output from leaking secrets via curl -v, GIT_TRACE, etc.)
// - fd > 2: only scrub for untrusted processes
//   (trusted tools need to send secrets over network sockets)
// ============================================================

SEC("tracepoint/syscalls/sys_enter_write")
int guard_write_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 zero = 0;
    __u32 *cnt = bpf_map_lookup_elem(&secret_count, &zero);
    if (!cnt || *cnt == 0) return 0;

    int fd = (int)ctx->args[0];

    // For fd > 2 (network/file), only block untrusted processes
    // Trusted processes can send secrets over sockets (git auth, curl, etc.)
    if (fd > 2 && is_trusted_pid())
        return 0;

    // For fd 0/1/2 (stdio): ALWAYS block regardless of trust
    // No legitimate reason for any process to write raw secret to terminal

    char *user_buf = (char *)ctx->args[1];
    __u64 user_len = ctx->args[2];

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
// READ MASKING — only for untrusted processes
// ============================================================

SEC("tracepoint/syscalls/sys_enter_read")
int guard_read_enter(struct trace_event_raw_sys_enter *ctx) {
    // Trusted processes read secrets unmasked
    if (is_trusted_pid())
        return 0;

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
        // Overwrite the full MAX_SECRET_LEN bytes to mask entire secret
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

// ============================================================
// AUTO-WATCH: hook openat to auto-add fds for secrets paths
// When an untrusted process opens a path containing "secrets" or ".env",
// the resulting fd is automatically added to watched_fds.
// We use sys_enter_openat to stash the path check, then sys_exit_openat
// to get the returned fd and add it to the map.
// ============================================================

#define SECRETS_PATH_LEN 32

// Per-tid stash: did this openat target a secrets file?
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);  // tid
    __type(value, __u8); // 1 = this was a secrets path open
} pending_opens SEC(".maps");

static __always_inline int is_secrets_path(char *path) {
    // Check for "secrets" or ".env" in path
    #pragma unroll
    for (int i = 0; i < SECRETS_PATH_LEN - 7; i++) {
        if (path[i] == 0) break;
        // "secrets"
        if (path[i] == 's' && path[i+1] == 'e' && path[i+2] == 'c' &&
            path[i+3] == 'r' && path[i+4] == 'e' && path[i+5] == 't')
            return 1;
        // ".env"
        if (path[i] == '.' && path[i+1] == 'e' && path[i+2] == 'n' &&
            path[i+3] == 'v')
            return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int guard_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    // Only track for untrusted processes
    if (is_trusted_pid())
        return 0;

    char *pathname = (char *)ctx->args[1];
    if (!pathname)
        return 0;

    char path[SECRETS_PATH_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    if (is_secrets_path(path)) {
        __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        __u8 val = 1;
        bpf_map_update_elem(&pending_opens, &tid, &val, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int guard_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u8 *pending = bpf_map_lookup_elem(&pending_opens, &tid);
    if (!pending)
        return 0;

    bpf_map_delete_elem(&pending_opens, &tid);

    // ret is the new fd (or negative error)
    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    // Add to watched_fds
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 fd_key = ((__u64)pid << 32) | (__u64)fd;
    __u8 val = 1;
    bpf_map_update_elem(&watched_fds, &fd_key, &val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
