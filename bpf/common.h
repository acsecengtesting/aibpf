// SPDX-License-Identifier: GPL-2.0
// Common definitions for aibpf BPF programs.
// Provides struct definitions that would normally come from vmlinux.h.

#ifndef __AIBPF_COMMON_H
#define __AIBPF_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Tracepoint context for sys_enter_* tracepoints.
// Matches the kernel's trace_event_raw_sys_enter layout.
struct trace_event_raw_sys_enter {
    unsigned long long unused;    // common fields (8 bytes)
    long id;                      // syscall number
    unsigned long args[6];        // syscall arguments
};

// Tracepoint context for sys_exit_* tracepoints.
struct trace_event_raw_sys_exit {
    unsigned long long unused;    // common fields (8 bytes)
    long id;                      // syscall number
    long ret;                     // return value
};

#endif /* __AIBPF_COMMON_H */
