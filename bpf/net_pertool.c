// SPDX-License-Identifier: GPL-2.0
// Per-tool network allowlist.
//
// Each trusted binary gets its own set of allowed destination IPs.
// Untrusted processes (from writable layer) get NO network access
// except localhost (for IPC with the supervisor).
//
// Uses cgroup/connect4 to intercept outbound TCP connections.
// Consults a per-PID allowlist populated by the loader based on policy.
//
// Maps:
//   trusted_pids       → shared with overlay_exec (which binary is trusted)
//   pid_to_tool        → maps PID → tool_id (which tool is this process)
//   tool_allowed_ips   → maps (tool_id, ip) → 1 (allowed destination for this tool)
//
// Flow:
//   1. connect4 fires
//   2. Allow localhost always (supervisor IPC)
//   3. Look up PID in trusted_pids — if not trusted, DENY
//   4. Look up PID in pid_to_tool — get tool_id
//   5. Look up (tool_id, dest_ip) in tool_allowed_ips — ALLOW or DENY

#include "common.h"
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#define MAX_TOOLS 32
#define MAX_IPS_PER_TOOL 64

// Shared: trusted PIDs from overlay_exec
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // pid
    __type(value, __u8);  // 1 = trusted
} trusted_pids SEC(".maps");

// PID → tool_id mapping (populated by loader at exec time)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // pid
    __type(value, __u32); // tool_id (0=git, 1=curl, 2=aws, etc.)
} pid_to_tool SEC(".maps");

// (tool_id, dest_ip) → allowed
// Key is 8 bytes: 4 bytes tool_id + 4 bytes IPv4 addr
struct tool_ip_key {
    __u32 tool_id;
    __u32 ip;  // network byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOOLS * MAX_IPS_PER_TOOL);
    __type(key, struct tool_ip_key);
    __type(value, __u8);
} tool_allowed_ips SEC(".maps");

// Deny events
struct net_deny_event {
    __u32 pid;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  trusted;
    __u8  reason;  // 0=untrusted, 1=no tool mapping, 2=dest not in tool allowlist
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} net_deny_events SEC(".maps");

SEC("cgroup/connect4")
int pertool_connect4(struct bpf_sock_addr *ctx) {
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = bpf_ntohs(ctx->user_port) >> 16;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Always allow localhost (supervisor IPC, proxy)
    if (dst_ip == bpf_htonl(0x7f000001))
        return 1;

    // Check if process is trusted
    __u8 *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (!trusted) {
        // Untrusted process — DENY all network
        struct net_deny_event evt = {
            .pid = pid,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .trusted = 0,
            .reason = 0,
        };
        bpf_perf_event_output(ctx, &net_deny_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return 0;
    }

    // Trusted process — check per-tool allowlist
    __u32 *tool_id = bpf_map_lookup_elem(&pid_to_tool, &pid);
    if (!tool_id) {
        // Trusted but no tool mapping — deny (fail-safe)
        struct net_deny_event evt = {
            .pid = pid,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .trusted = 1,
            .reason = 1,
        };
        bpf_perf_event_output(ctx, &net_deny_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return 0;
    }

    // Check if this tool is allowed to connect to this IP
    struct tool_ip_key key = {
        .tool_id = *tool_id,
        .ip = dst_ip,
    };
    __u8 *allowed = bpf_map_lookup_elem(&tool_allowed_ips, &key);
    if (allowed)
        return 1;  // ALLOW

    // Destination not in tool's allowlist — DENY
    struct net_deny_event evt = {
        .pid = pid,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .trusted = 1,
        .reason = 2,
    };
    bpf_perf_event_output(ctx, &net_deny_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
