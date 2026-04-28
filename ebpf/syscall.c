// SPDX-License-Identifier: GPL-2.0
// M6: Cgroup-scoped Syscall observability

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;

#define SLOW_SYSCALL_THRESHOLD_NS 50000000ULL // 50ms

struct syscall_key {
    u64 cgroup_id;
    u32 syscall_id;
    u32 pad;
};

struct syscall_stats {
    u64 count;
    u64 failures;
    u64 total_latency_ns;
};

struct slow_syscall_event {
    u64 cgroup_id;
    u32 pid;
    u32 syscall_id;
    u64 latency_ns;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // tid
    __type(value, u64); // ts
    __uint(max_entries, 65536);
} sys_enter_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
    __uint(max_entries, 8192);
} syscall_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} slow_syscall_rb SEC(".maps");

struct raw_syscalls_sys_enter_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    unsigned long  args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct raw_syscalls_sys_enter_args *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&sys_enter_ts, &tid, &ts, BPF_ANY);
    return 0;
}

struct raw_syscalls_sys_exit_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    long           ret;
};

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct raw_syscalls_sys_exit_args *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *ts_ptr = bpf_map_lookup_elem(&sys_enter_ts, &tid);
    if (!ts_ptr) {
        return 0; // Missed enter event
    }
    
    u64 start_ts = *ts_ptr;
    bpf_map_delete_elem(&sys_enter_ts, &tid);

    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 syscall_id = ctx->id;
    
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency = end_ts - start_ts;

    struct syscall_key key = {
        .cgroup_id = cgroup_id,
        .syscall_id = syscall_id,
    };

    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        struct syscall_stats initial = {};
        bpf_map_update_elem(&syscall_stats_map, &key, &initial, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    }

    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency);
        if (ctx->ret < 0) {
            __sync_fetch_and_add(&stats->failures, 1);
        }
    }

    if (latency > SLOW_SYSCALL_THRESHOLD_NS) {
        struct slow_syscall_event *event = bpf_ringbuf_reserve(&slow_syscall_rb, sizeof(*event), 0);
        if (event) {
            event->cgroup_id = cgroup_id;
            event->pid = tid >> 32;
            event->syscall_id = syscall_id;
            event->latency_ns = latency;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
