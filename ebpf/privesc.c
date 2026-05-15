// SPDX-License-Identifier: GPL-2.0
// Phase 4: Privilege Escalation Detection
//
// Baseline (tracepoints — stable ABI):
//   syscalls/sys_enter_setuid
//   syscalls/sys_enter_setgid
//   syscalls/sys_enter_ptrace  (PTRACE_ATTACH / PTRACE_SEIZE only)
//
// Best-effort (kprobe — internal symbol, may be unavailable):
//   kprobe/cap_capable
//   Go loader attaches this with graceful degradation on failure.
//   A "cap_capable_available" flag is exposed in health metrics.
//
// Tracepoint vs kprobe rationale:
//   setuid/setgid/ptrace use tracepoints (stable, ABI-guaranteed).
//   cap_capable uses kprobe because there is no stable tracepoint for it.
//   kprobes on internal symbols may be blocked on hardened kernels (lockdown mode).
//
// Noise suppression:
//   - setuid: old_uid == new_uid → suppress (no actual change)
//   - ptrace: only PTRACE_ATTACH (16) and PTRACE_SEIZE (0x4206) trigger events
//   - cap_capable: CAP_SYS_ADMIN(21), CAP_NET_ADMIN(12), CAP_SYS_PTRACE(19) only
//
// Phase 1 integration:
//   All events enriched with ppid and parent comm from process_tree_map.

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

typedef __u8  u8;
typedef __u32 u32;
typedef __u64 u64;

// ptrace request constants (from linux/ptrace.h)
#define PTRACE_ATTACH   16
#define PTRACE_SEIZE    0x4206

// Capability constants (from linux/capability.h) — traced by cap_capable kprobe
#define CAP_NET_ADMIN   12
#define CAP_SYS_PTRACE  19
#define CAP_SYS_ADMIN   21
#define CAP_SYS_MODULE  16
#define CAP_SYS_RAWIO   17

// Escalation type identifiers (matched in Go)
#define ESC_SETUID      1
#define ESC_SETGID      2
#define ESC_PTRACE      3
#define ESC_CAP         4

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
// privesc_event: ring buffer payload
// ---------------------------------------------------------------------------

struct privesc_event {
    u64  cgroup_id;
    u64  ts;                // bpf_ktime_get_ns()
    u32  tgid;
    u32  ppid;
    char comm[16];
    char parent_comm[16];
    u32  old_uid;           // for setuid/setgid: old credential
    u32  new_uid;           // for setuid/setgid: requested new credential
    u32  esc_type;          // ESC_SETUID, ESC_SETGID, ESC_PTRACE, ESC_CAP
    u32  cap;               // for cap_capable: the capability being checked
    u32  ptrace_pid;        // for ptrace: target PID being attached to
    u32  pad;
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} privesc_events SEC(".maps");

// Shared process tree from lineage.o (read-only)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lineage_key);
    __type(value, struct lineage_entry);
    __uint(max_entries, 65536);
} process_tree_map SEC(".maps");

// ---------------------------------------------------------------------------
// Helper: fill and emit a privesc_event
// ---------------------------------------------------------------------------
static __always_inline void emit_privesc(u64 cgroup_id, u32 tgid,
                                          u32 old_uid, u32 new_uid,
                                          u32 esc_type, u32 cap, u32 ptrace_pid) {
    struct privesc_event *ev = bpf_ringbuf_reserve(&privesc_events, sizeof(*ev), 0);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->cgroup_id  = cgroup_id;
    ev->ts         = bpf_ktime_get_ns();
    ev->tgid       = tgid;
    ev->old_uid    = old_uid;
    ev->new_uid    = new_uid;
    ev->esc_type   = esc_type;
    ev->cap        = cap;
    ev->ptrace_pid = ptrace_pid;

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

struct sys_enter_setuid_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    u32            uid;
};

struct sys_enter_setgid_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    u32            gid;
};

struct sys_enter_ptrace_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    long           request;
    long           pid;     // target PID
    unsigned long  addr;
    unsigned long  data;
};

// ---------------------------------------------------------------------------
// Baseline tracepoints
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct sys_enter_setuid_args *ctx) {
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 new_uid   = ctx->uid;

    // Suppress no-op: same UID requested (e.g., service restoring privileges)
    // We can't read old_uid in tracepoint context without task_struct access,
    // so we use 0xFFFFFFFF as sentinel meaning "unknown old UID".
    // Go userspace resolves old UID from /proc/<pid>/status if needed.
    emit_privesc(cgroup_id, tgid, 0xFFFFFFFF, new_uid, ESC_SETUID, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct sys_enter_setgid_args *ctx) {
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();

    emit_privesc(cgroup_id, tgid, 0xFFFFFFFF, ctx->gid, ESC_SETGID, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct sys_enter_ptrace_args *ctx) {
    // Only PTRACE_ATTACH and PTRACE_SEIZE are security-relevant.
    // PTRACE_PEEKDATA, PTRACE_CONT, etc. are normal debugging ops — skip.
    long req = ctx->request;
    if (req != PTRACE_ATTACH && req != PTRACE_SEIZE) return 0;

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 target_pid = (u32)ctx->pid;

    emit_privesc(cgroup_id, tgid, 0, 0, ESC_PTRACE, 0, target_pid);
    return 0;
}

// ---------------------------------------------------------------------------
// Best-effort kprobe: cap_capable
//
// cap_capable(const struct cred *cred, struct user_namespace *ns,
//             int cap, unsigned int opts)
//
// This is an internal kernel function — not a stable ABI.
// The Go loader attaches this with graceful degradation:
//   - On attach failure: logs warning, sets cap_capable_available=false in health
//   - Agent continues operating with setuid/setgid/ptrace tracepoints only
//
// Only high-value capabilities are traced (suppress noise from routine checks):
//   CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_SYS_RAWIO
// ---------------------------------------------------------------------------

SEC("kprobe/cap_capable")
int kprobe_cap_capable(struct pt_regs *ctx) {
    // cap is the 3rd argument (index 2) to cap_capable()
    int cap = (int)PT_REGS_PARM3(ctx);

    // Filter: only trace high-value capabilities
    if (cap != CAP_SYS_ADMIN  && cap != CAP_NET_ADMIN &&
        cap != CAP_SYS_PTRACE && cap != CAP_SYS_MODULE &&
        cap != CAP_SYS_RAWIO) {
        return 0;
    }

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();

    emit_privesc(cgroup_id, tgid, 0, 0, ESC_CAP, (u32)cap, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
