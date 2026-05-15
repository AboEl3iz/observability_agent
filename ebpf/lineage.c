// SPDX-License-Identifier: GPL-2.0
// Phase 1: Process Lineage Tracking
//
// Tracepoints: sched/sched_process_fork, sched/sched_process_exit
//
// Key design decisions (see implementation_plan.md for full rationale):
//
//  DISAMBIGUATION: Composite key (cgroup_id, tgid).
//    cgroup_id is already used by all existing modules (M1-M6); consistent.
//    Kernel requirement >= 5.5 for bpf_get_current_cgroup_id().
//    Project baseline is 5.8 (ring buffer). No additional constraint added.
//
//  TGID vs PID:
//    bpf_get_current_pid_tgid() >> 32 = tgid (userspace PID, thread group ID).
//    (u32)bpf_get_current_pid_tgid()  = tid  (kernel thread ID).
//    All maps keyed on tgid. Exit cleanup guard: delete only when tgid==tid.
//
//  COMM STALENESS: comm_final=0 at fork. exec.c sets comm_final=1 on execve.
//
//  DUAL MAP STRATEGY:
//    process_fork_rb  (RINGBUF, 4MB):   fire-and-forget per-fork events.
//    process_tree_map (LRU_HASH, 64Ki): live process tree for ancestry queries.
//    LRU_HASH chosen over HASH: SIGKILL'd processes bypass exit probe,
//    permanently leaking HASH entries. LRU eviction prevents unbounded growth.
//
//  MAX_ENTRIES = 65536: 2x headroom for 32-core server (~<=32K concurrent tgids).
//    On overflow: LRU evicts oldest entry (silent, by design).
//
//  OVERWRITE POLICY (BPF_ANY): PID reuse handled by always overwriting.
//    Old entry's lineage is lost on reuse — acceptable. Generation counters
//    are a documented future extension.
//
//  NOISE SUPPRESSION: ppid==2 (kthreadd children = kernel threads) filtered
//    in-kernel. Configurable via lineage_config[0] without recompile.
//    ppid==0 (idle) suppressed too. ppid==1 (init/systemd) NOT suppressed —
//    legitimate services are spawned by init and must be tracked.
//
//  INTER-MODULE CONTRACT:
//    process_tree_map is pinned by Go loader to /sys/fs/bpf/ebpf-agent/process_tree_map
//    and injected into exec.o, dns.o, privesc.o, escape.o via ebpf.MapReplacer.
//    Other BPF programs look up ancestry: key={cgroup_id,tgid} -> lineage_entry.

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u8  u8;
typedef __u32 u32;
typedef __u64 u64;

// ---------------------------------------------------------------------------
// Shared types — mirrored exactly in pkg/lineage/lineage.go and
// pkg/collector/lineage.go. Any changes here must be reflected in Go.
// ---------------------------------------------------------------------------

// lineage_key: composite key for PID-namespace-safe process tree lookup.
// tgid = bpf_get_current_pid_tgid() >> 32 = userspace-visible PID.
// pad ensures 8-byte struct alignment required by BPF verifier.
struct lineage_key {
    u64 cgroup_id;
    u32 tgid;
    u32 pad;
};

// lineage_entry: live state stored in process_tree_map.
// fork_ts uses bpf_ktime_get_ns() (ns since boot, NOT wall clock).
// Go userspace applies boot-time offset: wall_ns = fork_ts + bootTimeOffset.
// comm_final: 0 = placeholder (parent comm); 1 = real executable (set by exec.c).
struct lineage_entry {
    u32  ppid;
    u32  pad0;
    u64  cgroup_id;
    char comm[16];    // TASK_COMM_LEN=16
    u64  fork_ts;     // bpf_ktime_get_ns() — NOT wall clock
    u8   comm_final;  // 0=placeholder, 1=real exec name (Phase 2)
    u8   pad1[7];
};

// fork_event: emitted to process_fork_rb ring buffer on every non-kernel fork.
// Written unconditionally — this is the authoritative record for short-lived
// processes that exit before userspace can poll /proc/<pid>.
// Definition of "short-lived": exits before the Go poll interval elapses.
struct fork_event {
    u64  cgroup_id;
    u64  fork_ts;        // bpf_ktime_get_ns()
    u32  ppid;           // parent tgid
    u32  tgid;           // child tgid (new process PID)
    char parent_comm[16];
    char child_comm[16]; // same as parent_comm at fork; Phase 2 emits enriched event
    u8   comm_final;     // always 0 at fork time
    u8   pad[7];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Map A: ring buffer for fire-and-forget fork events.
// All non-suppressed forks are written here unconditionally.
// Back-pressure: bpf_ringbuf_reserve returns NULL when full — event is dropped.
// Userspace must drain this at least as fast as (4MB / avg_event_size) / fork_rate.
// At 256B/event and 1K forks/sec: ~16K events, 16s drain budget.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} process_fork_rb SEC(".maps");

// Map B: live process tree — shared with exec.c, dns.c, privesc.c, escape.c.
// Pinned to /sys/fs/bpf/ebpf-agent/process_tree_map by Go loader.
// Injected into other BPF collections via ebpf.CollectionOptions.MapReplacer.
// LRU eviction at max_entries=65536 prevents unbounded growth on high-churn hosts.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lineage_key);
    __type(value, struct lineage_entry);
    __uint(max_entries, 65536);
} process_tree_map SEC(".maps");

// Suppression config: index 0 = suppress_kernel_threads (default 1).
// Set to 0 via BPF map update to trace all processes without recompile.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 4);
} lineage_config SEC(".maps");

// ---------------------------------------------------------------------------
// Tracepoint context layouts
// Verified against /sys/kernel/debug/tracing/events/sched/*/format
// ---------------------------------------------------------------------------

struct sched_process_fork_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           parent_comm[16];
    u32            parent_pid;   // parent tgid
    char           child_comm[16];
    u32            child_pid;    // child tgid
};

struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           comm[16];
    u32            pid;
    int            prio;
};

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_fork
//
// Fires when a new process (tgid) is created via fork/clone.
// At this point child has NOT called execve — its comm copies the parent's.
// comm_final=0 is set as a placeholder. exec.c updates it on execve.
//
// Ring buffer write is UNCONDITIONAL (requirement 1.9: short-lived processes).
// Hash map write uses BPF_ANY (overwrite policy for PID reuse, requirement 1.10).
// ---------------------------------------------------------------------------
SEC("tracepoint/sched/sched_process_fork")
int trace_lineage_fork(struct sched_process_fork_args *ctx) {
    u32 ppid = ctx->parent_pid;

    // ── Noise suppression (requirement 1.11) ──────────────────────────────
    // ppid==2: kthreadd — all kernel threads are children of PID 2.
    // ppid==0: idle task. Both produce enormous noise with zero security value.
    // ppid==1 (init/systemd) is NOT suppressed — legitimate services tracked.
    // Configurable via lineage_config[0]: 0=trace-all, 1=suppress (default).
    u32 cfg_key = 0;
    u32 *suppress = bpf_map_lookup_elem(&lineage_config, &cfg_key);
    u32 do_suppress = suppress ? *suppress : 1;
    if (do_suppress && (ppid == 0 || ppid == 2)) {
        return 0;
    }

    u64 cgroup_id = bpf_get_current_cgroup_id();
    u64 ts        = bpf_ktime_get_ns();
    u32 child_tgid = ctx->child_pid;

    // ── Ring buffer write (requirement 1.9 — unconditional) ───────────────
    struct fork_event *ev = bpf_ringbuf_reserve(&process_fork_rb, sizeof(*ev), 0);
    if (ev) {
        ev->cgroup_id  = cgroup_id;
        ev->fork_ts    = ts;
        ev->ppid       = ppid;
        ev->tgid       = child_tgid;
        ev->comm_final = 0;
        __builtin_memcpy(ev->parent_comm, ctx->parent_comm, 16);
        __builtin_memcpy(ev->child_comm,  ctx->child_comm,  16);
        bpf_ringbuf_submit(ev, 0);
    }
    // reserve failure = ring buffer full; event dropped. Intentional.

    // ── LRU hash write (requirement 1.4 Map B) ───────────────────────────
    struct lineage_key key = {
        .cgroup_id = cgroup_id,
        .tgid      = child_tgid,
        .pad       = 0,
    };
    struct lineage_entry entry = {
        .ppid       = ppid,
        .pad0       = 0,
        .cgroup_id  = cgroup_id,
        .fork_ts    = ts,
        .comm_final = 0,
    };
    __builtin_memcpy(entry.comm, ctx->child_comm, 16);

    // BPF_ANY = overwrite policy (requirement 1.10: PID reuse handled by overwrite).
    bpf_map_update_elem(&process_tree_map, &key, &entry, BPF_ANY);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_exit
//
// Fires once per kernel thread (tid), NOT once per process.
// Multi-threaded processes fire this N times (once per thread).
//
// Cleanup guard (requirement 1.6):
//   Only delete the process_tree_map entry when the MAIN THREAD exits
//   (tgid == tid). This prevents destroying lineage for remaining threads.
// ---------------------------------------------------------------------------
SEC("tracepoint/sched/sched_process_exit")
int trace_lineage_exit(struct sched_process_exit_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32); // userspace PID (thread group ID)
    u32 tid  = (u32)(pid_tgid);       // kernel thread ID

    // CRITICAL: only delete when the main thread exits.
    // A thread exit (tgid != tid) must NOT remove the shared process entry.
    if (tgid != tid) {
        return 0;
    }

    u64 cgroup_id = bpf_get_current_cgroup_id();
    struct lineage_key key = {
        .cgroup_id = cgroup_id,
        .tgid      = tgid,
        .pad       = 0,
    };
    bpf_map_delete_elem(&process_tree_map, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
