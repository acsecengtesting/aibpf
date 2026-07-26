// SPDX-License-Identifier: GPL-2.0
// Overlay-aware exec guard: blocks secret access for anything running
// from the writable (upper) layer of an overlayfs.
//
// Trust model:
//   - Read-only layer binaries (image layer) = TRUSTED, get secrets
//   - Writable layer binaries (agent-created) = UNTRUSTED, no secrets
//
// This is hooked at execve time. If the binary being executed has an
// upperdentry in the overlay inode (meaning it was written to the container's
// writable layer), we mark that PID as untrusted. The secret_guard BPF
// then consults this to decide whether to SIGKILL on secret access.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 128

// Overlay inode structure (kernel internal)
struct ovl_inode___local {
    union {
        void *cache;
        const char *lowerdata_redirect;
    };
    const char *redirect;
    __u64 version;
    unsigned long flags;
    struct inode vfs_inode;
    struct dentry *__upperdentry;
} __attribute__((preserve_access_index));

// Map of untrusted PIDs (from writable layer)
// Key: pid, Value: 1 = untrusted
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} untrusted_pids SEC(".maps");

// Map of trusted PIDs (from read-only layer) — for auditing
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} trusted_pids SEC(".maps");

// Host mount namespace (set by userspace) — skip host processes
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} host_mnt_ns SEC(".maps");

// Events for logging
struct exec_trust_event {
    __u32 pid;
    __u8  trusted;     // 1 = from read-only layer, 0 = from writable layer
    __u8  is_overlay;  // 1 = overlayfs, 0 = other fs
    char  filename[MAX_PATH];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_trust_events SEC(".maps");

// Hook: after execve completes successfully, check if the binary
// came from the overlay upper layer.
SEC("kprobe/ovl_open")
int BPF_KPROBE(ovl_exec_check, struct inode *inode, struct file *file)
{
    // Get current task's mount namespace
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 mnt_ns_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    // Skip host processes
    __u32 key = 0;
    __u64 *host_ns = bpf_map_lookup_elem(&host_mnt_ns, &key);
    if (host_ns && mnt_ns_inum == *host_ns)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if this file has an upper dentry (writable layer)
    struct ovl_inode___local *oi;
    oi = container_of(inode, struct ovl_inode___local, vfs_inode);
    struct dentry *upper = BPF_CORE_READ(oi, __upperdentry);

    struct exec_trust_event *e = bpf_ringbuf_reserve(&exec_trust_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->is_overlay = 1;
    __builtin_memset(e->filename, 0, MAX_PATH);
    __builtin_memset(e->comm, 0, 16);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Read filename
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(e->filename, MAX_PATH, d_name.name);
    }

    if (upper) {
        // File is from writable layer — UNTRUSTED
        e->trusted = 0;
        __u8 val = 1;
        bpf_map_update_elem(&untrusted_pids, &pid, &val, BPF_ANY);
        // Remove from trusted if it was there
        bpf_map_delete_elem(&trusted_pids, &pid);
    } else {
        // File is from read-only layer — TRUSTED
        e->trusted = 1;
        __u8 val = 1;
        bpf_map_update_elem(&trusted_pids, &pid, &val, BPF_ANY);
        // Remove from untrusted if it was there
        bpf_map_delete_elem(&untrusted_pids, &pid);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Also track process exit to clean up maps
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&untrusted_pids, &pid);
    bpf_map_delete_elem(&trusted_pids, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
