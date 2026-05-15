// SPDX-License-Identifier: GPL-2.0
// Phase 5: Container Escape Indicators
//
// Tracepoints:
//   syscalls/sys_enter_mount
//   syscalls/sys_enter_unshare
//   syscalls/sys_enter_pivot_root
//
// These syscalls are the primary indicators of container escape attempts:
//
//   mount:      Binding host paths into a container filesystem, or remounting
//               as read-write. Legitimate inside containers only with CAP_SYS_ADMIN.
//
//   unshare:    Creating new namespaces from within a container. Suspicious flags:
//               CLONE_NEWNS (mount ns), CLONE_NEWPID (pid ns), CLONE_NEWNET (net ns).
//               Legitimate use: container runtimes at startup (containerd-shim, runc).
//
//   pivot_root: Changing the root filesystem. Almost exclusively called by container
//               runtimes during initial setup. A subsequent pivot_root from inside a
//               running container is a very high-confidence escape indicator.
//
// False positive handling:
//   pivot_root: Expected from container runtimes (runc, containerd-shim) at startup.
//               Go userspace filters based on parent process name (lentry->comm).
//               If parent_comm matches "runc", "containerd-shim", "dockerd" → lower signal.
//
// Phase 1 integration:
//   All events enriched with ppid and parent_comm from process_tree_map.
//   Downstream security logic uses ancestry to determine if caller is a
//   known runtime (expected) vs a workload process (suspicious).

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u8  u8;
typedef __u32 u32;
typedef __u64 u64;

// Indicator type identifiers (matched in Go)
#define IND_MOUNT       1
#define IND_UNSHARE     2
#define IND_PIVOT_ROOT  3

// clone/unshare namespace flags (from linux/sched.h)
#define CLONE_NEWNS     0x00020000  // mount namespace
#define CLONE_NEWPID    0x20000000  // PID namespace
#define CLONE_NEWNET    0x40000000  // network namespace
#define CLONE_NEWUSER   0x10000000  // user namespace
#define CLONE_NEWUTS    0x04000000  // UTS namespace
#define CLONE_NEWIPC    0x08000000  // IPC namespace

// High-signal unshare flags (any of these = suspicious from workload context)
#define SUSPICIOUS_NS_FLAGS (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUSER)

// ---------------------------------------------------------------------------
// Shared types — must match lineage.c
// ---------------------------------------------------------------------------

struct lineage_key {
    u64 cgroup_id;
    u32 tgid;
    u32 pad;
};

struct lineage_entry {
    u32  ppid;
    u32  pad0;
    u64  cgroup_id;
    char comm[16];
    u64  fork_ts;
    u8   comm_final;
    u8   pad1[7];
};

// ---------------------------------------------------------------------------
// escape_event: ring buffer payload
// ---------------------------------------------------------------------------

struct escape_event {
    u64  cgroup_id;
    u64  ts;                  // bpf_ktime_get_ns()
    u32  tgid;
    u32  ppid;
    char comm[16];            // calling process
    char parent_comm[16];     // parent process (from lineage)
    u32  indicator_type;      // IND_MOUNT, IND_UNSHARE, IND_PIVOT_ROOT
    u32  ns_flags;            // unshare: clone flags; mount: mount flags; pivot: 0
    u8   pad[8];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} escape_events SEC(".maps");

// Shared process tree from lineage.o (read-only)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lineage_key);
    __type(value, struct lineage_entry);
    __uint(max_entries, 65536);
} process_tree_map SEC(".maps");

// ---------------------------------------------------------------------------
// Helper: fill and submit an escape_event
// ---------------------------------------------------------------------------
static __always_inline void emit_escape(u64 cgroup_id, u32 tgid,
                                         u32 indicator_type, u32 ns_flags) {
    struct escape_event *ev = bpf_ringbuf_reserve(&escape_events, sizeof(*ev), 0);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->cgroup_id      = cgroup_id;
    ev->ts             = bpf_ktime_get_ns();
    ev->tgid           = tgid;
    ev->indicator_type = indicator_type;
    ev->ns_flags       = ns_flags;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    struct lineage_key lkey = { .cgroup_id = cgroup_id, .tgid = tgid, .pad = 0 };
    struct lineage_entry *lentry = bpf_map_lookup_elem(&process_tree_map, &lkey);
    if (lentry) {
        ev->ppid = lentry->ppid;
        __builtin_memcpy(ev->parent_comm, lentry->comm, 16);
    }

    bpf_ringbuf_submit(ev, 0);
}

// ---------------------------------------------------------------------------
// Tracepoint context layouts
// ---------------------------------------------------------------------------

struct sys_enter_mount_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    char          *dev_name;    // source
    char          *dir_name;    // target mountpoint
    char          *type;        // filesystem type
    unsigned long  flags;       // mount flags (MS_BIND, MS_RDONLY, etc.)
    void          *data;        // fs-specific options
};

struct sys_enter_unshare_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    unsigned long  unshare_flags; // CLONE_NEW* flags
};

struct sys_enter_pivot_root_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    const char    *new_root;
    const char    *put_old;
};

// ---------------------------------------------------------------------------
// Tracepoints
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct sys_enter_mount_args *ctx) {
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 flags     = (u32)ctx->flags;

    emit_escape(cgroup_id, tgid, IND_MOUNT, flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct sys_enter_unshare_args *ctx) {
    u32 ns_flags = (u32)ctx->unshare_flags;

    // Only emit events for security-relevant namespace flags.
    // Filtering here reduces event volume significantly:
    //   CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWUSER = suspicious
    //   Other flags (CLONE_FILES, CLONE_FS, etc.) = low security value
    if (!(ns_flags & SUSPICIOUS_NS_FLAGS)) return 0;

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();

    emit_escape(cgroup_id, tgid, IND_UNSHARE, ns_flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_pivot_root(struct sys_enter_pivot_root_args *ctx) {
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();

    // Emit all pivot_root calls — Go userspace applies runtime-parent filter.
    // pivot_root from a workload process (non-runtime parent) is high-confidence escape.
    emit_escape(cgroup_id, tgid, IND_PIVOT_ROOT, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
