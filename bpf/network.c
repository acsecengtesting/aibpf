// SPDX-License-Identifier: GPL-2.0
// Network policy enforcement via cgroup/connect4.
// Allows/denies outbound connections based on dest IP and port.

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Max entries in allow/deny maps
#define MAX_RULES 256

// Rule: ip (network order), port (host order), prefix_len for CIDR
struct net_rule {
    __u32 addr;        // IPv4 in network byte order, 0 = any
    __u16 port;        // 0 = any port
    __u8  prefix_len;  // CIDR prefix, 0 = exact match on addr
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_rule);
} allow_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_rule);
} deny_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rule_counts SEC(".maps"); // [0] = allow_count, but we use two keys

// Check if addr matches rule (considering CIDR prefix)
static __always_inline int addr_match(__u32 addr, struct net_rule *r) {
    if (r->addr == 0) return 1; // wildcard
    if (r->prefix_len == 0 || r->prefix_len == 32) {
        return addr == r->addr;
    }
    __u32 mask = bpf_htonl(0xFFFFFFFF << (32 - r->prefix_len));
    return (addr & mask) == (r->addr & mask);
}

static __always_inline int port_match(__u16 port, struct net_rule *r) {
    if (r->port == 0) return 1; // wildcard
    return port == r->port;
}

SEC("cgroup/connect4")
int aibpf_connect4(struct bpf_sock_addr *ctx) {
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = bpf_ntohs(ctx->user_port) >> 16;

    // Allow localhost always (proxy communication)
    if (dst_ip == bpf_htonl(0x7f000001)) {
        return 1; // allow
    }

    // Check deny rules first
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct net_rule *r = bpf_map_lookup_elem(&deny_rules, &key);
        if (!r || (r->addr == 0 && r->port == 0)) break;
        if (addr_match(dst_ip, r) && port_match(dst_port, r)) {
            return 0; // deny
        }
    }

    // Check allow rules
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct net_rule *r = bpf_map_lookup_elem(&allow_rules, &key);
        if (!r || (r->addr == 0 && r->port == 0)) break;
        if (addr_match(dst_ip, r) && port_match(dst_port, r)) {
            return 1; // allow
        }
    }

    // Default deny - agent must go through proxy
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
