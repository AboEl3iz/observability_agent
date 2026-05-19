// SPDX-License-Identifier: GPL-2.0
// M2: Memory & OOM Kill Root Cause
//
// Probes:
//   tracepoint/oom/mark_victim   — fires when the OOM killer selects a victim
//   tracepoint/exceptions/page_fault_user — user-space page faults (RSS proxy)
//
// Ring buffer: oom_events (one entry per OOM kill)
// Hash map:    page_fault_map  (per-cgroup cumulative minor + major fault counts)

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u16 u16;
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

// Per-cgroup page fault accumulator — minor and major separated
// Major faults = demand-paging (page not present, requires disk I/O)
// Minor faults = anon/CoW/protection violations (no disk I/O)
struct pf_stats {
    u64 minor_faults; // cumulative minor user faults
    u64 major_faults; // cumulative major (demand-paging) user faults
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
// Modern Kernel tracepoint format (matched to user's system):
//   field:int pid;                      offset:8;  size:4;
//   field:__data_loc char[] comm;       offset:12; size:4;
//   field:unsigned long total_vm;       offset:16; size:8;
//   field:unsigned long anon_rss;       offset:24; size:8;
//   field:unsigned long file_rss;       offset:32; size:8;
//   field:unsigned long shmem_rss;      offset:40; size:8;
//   field:uid_t uid;                    offset:48; size:4;
//   field:unsigned long pgtables;       offset:56; size:8;
//   field:short oom_score_adj;          offset:64; size:2;
// ---------------------------------------------------------------------------
struct mark_victim_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    int            pid;
    u32            comm; // __data_loc string index (offset/len)
    unsigned long  total_vm;
    unsigned long  anon_rss;
    unsigned long  file_rss;
    unsigned long  shmem_rss;
    u32            uid;
    unsigned long  pgtables;
    short          oom_score_adj;
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
    // Total RSS pages is anon + file + shmem
    ev->pages        = (u64)(ctx->anon_rss + ctx->file_rss + ctx->shmem_rss);

    // Resolve __data_loc dynamic string for comm
    u16 comm_offset = ctx->comm & 0xffff;
    bpf_probe_read_kernel_str(ev->comm, sizeof(ev->comm), (void *)ctx + comm_offset);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/exceptions/page_fault_user
//
// Fires on every user-space page fault.
//
// x86 page-fault error_code bits (written to CR2):
//   bit 0 (PF_PROT)  : 1 = protection violation (minor: anon/CoW, no disk I/O)
//                      0 = page not present     (MAJOR: demand-paging, needs disk)
//   bit 1 (PF_WRITE) : write access triggered the fault
//   bit 2 (PF_USER)  : fault from user mode
//   bit 4 (PF_INSTR) : instruction fetch fault
//
// Classification:
//   PF_PROT clear (0) → page not in memory → MAJOR fault (disk I/O required)
//   PF_PROT set   (1) → protection/CoW fault → MINOR fault (no disk I/O)
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

// PF_PROT: protection fault bit in x86 error_code
#define PF_PROT 0x1UL

SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault_user(struct page_fault_user_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    struct pf_stats *s = bpf_map_lookup_elem(&page_fault_map, &cgroup_id);
    if (!s) {
        struct pf_stats zero = {};
        if (ctx->error_code & PF_PROT) {
            zero.minor_faults = 1;
        } else {
            zero.major_faults = 1;
        }
        bpf_map_update_elem(&page_fault_map, &cgroup_id, &zero, BPF_NOEXIST);
        return 0;
    }

    if (ctx->error_code & PF_PROT) {
        __sync_fetch_and_add(&s->minor_faults, 1);
    } else {
        __sync_fetch_and_add(&s->major_faults, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
