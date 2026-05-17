// SPDX-License-Identifier: GPL-2.0
// M0 + M1: Cgroup-scoped CPU & Thread observability
// Probes: sched_switch, sched_wakeup, sched_process_fork, sched_process_exit

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;

// ---------------------------------------------------------------------------
// Shared data structures (M0: cgroup-keyed)
// ---------------------------------------------------------------------------

// Key for per-cgroup CPU stats map
struct cpu_key {
    u64 cgroup_id;
};

// Value: per-cgroup CPU accounting (M1)
struct cpu_stats {
    u64 total_ns;         // total on-CPU nanoseconds (across all tasks in cgroup)
    u64 runq_latency_ns;  // cumulative runqueue wait nanoseconds
    u64 ctx_switches;     // voluntary + involuntary context switches
    u32 thread_count;     // live thread gauge (fork - exit)
    u32 pad;
};

// Scratch map: pid -> schedule-in timestamp (for on-CPU time measurement)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // pid
    __type(value, u64); // ktime_ns when scheduled in
    __uint(max_entries, 65536);
} sched_in_ts SEC(".maps");

// Scratch map: pid -> wakeup timestamp (for runqueue latency)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // pid
    __type(value, u64); // ktime_ns at wakeup
    __uint(max_entries, 65536);
} wakeup_ts SEC(".maps");

// Scratch map: pid -> cgroup_id (carried across sched_wakeup → sched_switch)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // pid
    __type(value, u64); // cgroup_id
    __uint(max_entries, 65536);
} pid_cgroup SEC(".maps");

// Main output map: cgroup_id -> cpu_stats (M1 result)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct cpu_key);
    __type(value, struct cpu_stats);
    __uint(max_entries, 1024);
} cpu_stats_map SEC(".maps");

// ---------------------------------------------------------------------------
// Helper: upsert a cpu_stats entry, returning a pointer to it
// ---------------------------------------------------------------------------
static __always_inline struct cpu_stats *get_or_create_stats(u64 cgroup_id) {
    struct cpu_key k = { .cgroup_id = cgroup_id };
    struct cpu_stats *s = bpf_map_lookup_elem(&cpu_stats_map, &k);
    if (!s) {
        struct cpu_stats zero = {};
        bpf_map_update_elem(&cpu_stats_map, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&cpu_stats_map, &k);
    }
    return s;
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_switch
//
// Fired when a task is descheduled. The task being replaced is the PREVIOUS
// task (prev_*). The next task (next_*) is what runs after.
//
// We:
//   1. Record schedule-out for the PREV task → compute on-CPU time
//   2. Record schedule-in timestamp for the NEXT task
// ---------------------------------------------------------------------------

// Minimal tracepoint context layout for sched_switch
struct sched_switch_args {
    // common fields (trace_entry) — 8 bytes
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    char           prev_comm[16];
    u32            prev_pid;
    int            prev_prio;
    long           prev_state;
    char           next_comm[16];
    u32            next_pid;
    int            next_prio;
};

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct sched_switch_args *ctx) {
    u64 ts = bpf_ktime_get_ns();

    // --- PREV task: measure on-CPU time ---
    u32 prev_pid = ctx->prev_pid;
    u64 *in_ts = bpf_map_lookup_elem(&sched_in_ts, &prev_pid);
    if (in_ts) {
        u64 delta = ts - *in_ts;
        bpf_map_delete_elem(&sched_in_ts, &prev_pid);

        // Look up cgroup for this pid (saved on wakeup or fallback to current)
        u64 cgroup_id;
        u64 *saved_cg = bpf_map_lookup_elem(&pid_cgroup, &prev_pid);
        if (saved_cg) {
            cgroup_id = *saved_cg;
        } else {
            cgroup_id = bpf_get_current_cgroup_id();
        }

        struct cpu_stats *s = get_or_create_stats(cgroup_id);
        if (s) {
            __sync_fetch_and_add(&s->total_ns, delta);
            __sync_fetch_and_add(&s->ctx_switches, 1);
        }

        // Compute runqueue latency: wakeup_ts was stored by sched_wakeup
        u64 *wk_ts = bpf_map_lookup_elem(&wakeup_ts, &prev_pid);
        if (wk_ts) {
            // prev is being switched OUT now; runq latency was already applied
            // when it was scheduled IN. Clean up.
            bpf_map_delete_elem(&wakeup_ts, &prev_pid);
        }
        bpf_map_delete_elem(&pid_cgroup, &prev_pid);
    }

    // --- NEXT task: record schedule-in timestamp ---
    u32 next_pid = ctx->next_pid;
    u64 cgroup_id = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&sched_in_ts, &next_pid, &ts, BPF_ANY);
    bpf_map_update_elem(&pid_cgroup, &next_pid, &cgroup_id, BPF_ANY);

    // If we have a wakeup timestamp for next_pid, compute runq latency
    u64 *wk_ts = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (wk_ts) {
        u64 latency = ts - *wk_ts;
        struct cpu_stats *s = get_or_create_stats(cgroup_id);
        if (s) {
            __sync_fetch_and_add(&s->runq_latency_ns, latency);
        }
        bpf_map_delete_elem(&wakeup_ts, &next_pid);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_wakeup
//
// Fired when a sleeping task is made runnable. Record the wakeup timestamp
// so sched_switch can compute runqueue latency.
// ---------------------------------------------------------------------------

struct sched_wakeup_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           comm[16];
    u32            pid;
    int            prio;
    int            target_cpu;
};

SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct sched_wakeup_args *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 pid = ctx->pid;
    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_fork
//
// Fired on fork(). Increment the thread counter for the parent's cgroup.
// ---------------------------------------------------------------------------

struct sched_process_fork_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           parent_comm[16];
    u32            parent_pid;
    char           child_comm[16];
    u32            child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_fork(struct sched_process_fork_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cpu_stats *s = get_or_create_stats(cgroup_id);
    if (s) {
        __sync_fetch_and_add(&s->thread_count, 1);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_exit
//
// Fired on task exit. Decrement the thread counter.
// Also clean up scratch maps for this pid.
// ---------------------------------------------------------------------------

struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           comm[16];
    u32            pid;
    int            prio;
};

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(struct sched_process_exit_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cpu_stats *s = get_or_create_stats(cgroup_id);
    if (s) {
        if (s->thread_count > 0) {
            __sync_fetch_and_add(&s->thread_count, -1);
            // Post-decrement guard: if a race caused underflow, s->thread_count wraps to max uint32
            if (s->thread_count > 1000000) {
                s->thread_count = 0;
            }
        }
    }

    // Clean up scratch state for this pid
    u32 pid = ctx->pid;
    bpf_map_delete_elem(&sched_in_ts, &pid);
    bpf_map_delete_elem(&wakeup_ts, &pid);
    bpf_map_delete_elem(&pid_cgroup, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
