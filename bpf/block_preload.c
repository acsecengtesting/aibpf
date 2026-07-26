// SPDX-License-Identifier: GPL-2.0
// Block LD_PRELOAD and LD_LIBRARY_PATH from being used.
//
// Any process that attempts to execve with LD_PRELOAD or LD_LIBRARY_PATH
// in its environment is killed. This prevents injecting malicious shared
// libraries into trusted binaries.
//
// Hook: tracepoint/syscalls/sys_enter_execve
// Scans the envp array for dangerous environment variables.

#include "common.h"

#define MAX_ENV_SCAN 20      // max number of env vars to check
#define ENV_VAR_LEN 16       // only need to read first 16 bytes of each

// Prefixes to block
// LD_PRELOAD= (11 chars)
// LD_LIBRARY_PATH= (16 chars)
#define LD_PRELOAD_PREFIX "LD_PRELOAD="
#define LD_LIBPATH_PREFIX "LD_LIBRARY_PATH="

struct preload_event {
    __u32 pid;
    char  comm[16];
    char  var_prefix[ENV_VAR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} preload_events SEC(".maps");

// Config: enable/disable (allows toggling without unloading)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);  // 1 = blocking enabled
} preload_config SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int block_ld_preload(struct trace_event_raw_sys_enter *ctx) {
    // Check if blocking is enabled
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&preload_config, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    // args[2] is envp (char **)
    unsigned long *envp_ptr = (unsigned long *)ctx->args[2];
    if (!envp_ptr)
        return 0;

    // Scan environment variables
    #pragma unroll
    for (int i = 0; i < MAX_ENV_SCAN; i++) {
        unsigned long env_entry = 0;
        if (bpf_probe_read_user(&env_entry, sizeof(env_entry), &envp_ptr[i]) < 0)
            break;
        if (env_entry == 0)  // NULL terminator
            break;

        // Read first ENV_VAR_LEN bytes of this env var
        char buf[ENV_VAR_LEN] = {};
        if (bpf_probe_read_user_str(buf, sizeof(buf), (void *)env_entry) < 0)
            continue;

        // Fast check: starts with "LD_" (3 bytes)
        if (buf[0] != 'L' || buf[1] != 'D' || buf[2] != '_')
            continue;

        // Check LD_PRELOAD= (buf[3]=='P' and buf[10]=='=')
        // Check LD_LIBRARY_PATH= (buf[3]=='L')
        int dangerous = 0;
        if (buf[3] == 'P' && buf[4] == 'R' && buf[5] == 'E')
            dangerous = 1;
        if (buf[3] == 'L' && buf[4] == 'I' && buf[5] == 'B')
            dangerous = 1;

        if (dangerous) {
            struct preload_event evt = {};
            evt.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(evt.comm, sizeof(evt.comm));
            #pragma unroll
            for (int k = 0; k < ENV_VAR_LEN; k++)
                evt.var_prefix[k] = buf[k];

            bpf_perf_event_output(ctx, &preload_events,
                BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            bpf_send_signal(9);
            return 0;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
