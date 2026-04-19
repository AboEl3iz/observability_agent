// SPDX-License-Identifier: GPL-2.0
// M2: Memory & OOM Kill Root Cause
//
// Probes:
//   tracepoint/oom/mark_victim   — fires when the OOM killer selects a victim
//   tracepoint/exceptions/page_fault_user — user-space page faults (RSS proxy)
//
// Ring buffer: oom_events (one entry per OOM kill)
// Hash map:    page_fault_map  (per-cgroup cumulative fault counts)

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

// OOM event shipped to userspace via ring buffer
struct oom_event {
    u64 cgroup_id;
    u32 victim_pid;
    u32 oom_score_adj;  // /proc/<pid>/oom_score_adj value (not directly available
                         // in the tracepoint; we store 0 and let userspace read it)
    u64 pages;           // number of pages owned by victim at kill time
    char comm[16];       // victim command name
};

// Per-cgroup page fault accumulator
struct pf_stats {
    u64 faults; // cumulative minor+major user faults
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ring buffer for OOM events (4 MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} oom_events SEC(".maps");

// Per-cgroup page fault counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   u64);           // cgroup_id
    __type(value, struct pf_stats);
    __uint(max_entries, 1024);
} page_fault_map SEC(".maps");

// ---------------------------------------------------------------------------
// tracepoint/oom/mark_victim
//
// Kernel tracepoint format (from /sys/kernel/debug/tracing/events/oom/mark_victim/format):
//   field:int pid;      offset:8;  size:4;
//   field:char comm[TASK_COMM_LEN]; offset:12; size:16;
//   field:oom_flags_t oom_flags; ...
//   field:long totalpages; ...
// ---------------------------------------------------------------------------
struct mark_victim_args {
    // trace_entry common fields (8 bytes)
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    int            pid;
    char           comm[16];
    unsigned long  totalpages;
    int            oom_score_adj;
};

SEC("tracepoint/oom/mark_victim")
int trace_oom_mark_victim(struct mark_victim_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    struct oom_event *ev = bpf_ringbuf_reserve(&oom_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->cgroup_id    = cgroup_id;
    ev->victim_pid   = (u32)ctx->pid;
    ev->oom_score_adj = (u32)ctx->oom_score_adj;
    ev->pages        = (u64)ctx->totalpages;
    __builtin_memcpy(ev->comm, ctx->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/exceptions/page_fault_user
//
// Fires on every user-space page fault (minor + major).
// We use this as a proxy for RSS growth / swap-in activity.
// ---------------------------------------------------------------------------
struct page_fault_user_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    unsigned long  address;   // fault virtual address
    unsigned long  ip;        // instruction pointer
    unsigned long  error_code;
};

SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault_user(struct page_fault_user_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    struct pf_stats *s = bpf_map_lookup_elem(&page_fault_map, &cgroup_id);
    if (!s) {
        struct pf_stats zero = { .faults = 1 };
        bpf_map_update_elem(&page_fault_map, &cgroup_id, &zero, BPF_NOEXIST);
        return 0;
    }
    __sync_fetch_and_add(&s->faults, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
