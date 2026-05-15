// SPDX-License-Identifier: GPL-2.0
// Phase 2: Full Execve Argument Capture
//
// Tracepoint: syscalls/sys_enter_execve
//
// Captures: executable path, argv (bounded), pid/tgid, ppid, cgroup_id.
//
// Memory safety:
//   - Per-CPU scratch array (PERCPU_ARRAY, 1 slot) used as argv assembly buffer.
//     Avoids BPF stack overflow: stack limit is 512 bytes; exec_event is ~2.4KB.
//   - All argv loops use #pragma unroll with compile-time-constant bounds.
//   - bpf_probe_read_user / bpf_probe_read_user_str for safe user-ptr reads.
//   - Truncation flags set explicitly — consumers know when data is incomplete.
//
// Phase 1 integration (requirement 1.3 — two-phase enrichment):
//   On execve this program:
//     1. Looks up process_tree_map[{cgroup_id, tgid}]
//     2. Writes real executable comm into lineage entry
//     3. Sets comm_final = 1
//   process_tree_map is shared from lineage.o via Go MapReplacer.
//
// Bounds:
//   MAX_ARGS      = 20   (configurable at compile time)
//   MAX_ARG_LEN   = 128  bytes per argument
//   MAX_TOTAL_LEN = 2048 bytes total argv buffer
//   EXEC_PATH_LEN = 256  bytes for executable path

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u8  u8;
typedef __u32 u32;
typedef __u64 u64;

#define MAX_ARGS       20
#define MAX_ARG_LEN    128
#define MAX_TOTAL_LEN  2048
#define EXEC_PATH_LEN  256

// ---------------------------------------------------------------------------
// Shared types — must match lineage.c exactly
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
// exec_event: ring buffer payload
// ---------------------------------------------------------------------------

struct exec_event {
    u64  cgroup_id;
    u64  ts;                       // bpf_ktime_get_ns()
    u32  tgid;
    u32  ppid;
    char path[EXEC_PATH_LEN];      // null-terminated executable path
    char argv[MAX_TOTAL_LEN];      // packed args, each null-terminated
    u32  argv_count;               // number of args captured
    u32  argv_total_len;           // bytes written into argv buffer
    u8   argv_truncated;           // 1 if arg count or total len was exceeded
    u8   path_truncated;           // 1 if path was longer than EXEC_PATH_LEN
    u8   pad[6];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Per-CPU scratch buffer: avoids 512-byte BPF stack limit.
// PERCPU_ARRAY with 1 slot: zero-index access, no lock needed (per-CPU).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct exec_event);
    __uint(max_entries, 1);
} exec_scratch SEC(".maps");

// Ring buffer for execve events. 8MB: larger payloads than fork events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} exec_events SEC(".maps");

// Shared process tree — injected from lineage.o via Go MapReplacer.
// This program writes comm_final updates; all other programs read only.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lineage_key);
    __type(value, struct lineage_entry);
    __uint(max_entries, 65536);
} process_tree_map SEC(".maps");

// ---------------------------------------------------------------------------
// Tracepoint context layout for sys_enter_execve
// Verified against: /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
// ---------------------------------------------------------------------------

struct sys_enter_execve_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    const char     *filename;          // user-space pointer
    const char *const *argv;           // user-space pointer array
    const char *const *envp;           // not captured
};

// ---------------------------------------------------------------------------
// tracepoint/syscalls/sys_enter_execve
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct sys_enter_execve_args *ctx) {
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u64 cgroup_id = bpf_get_current_cgroup_id();

    // ── Per-CPU scratch (avoids stack overflow) ────────────────────────────
    u32 zero = 0;
    struct exec_event *ev = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!ev) return 0;

    // Reset mutable fields individually — BPF verifier rejects __builtin_memset
    // on map value pointers. Per-CPU array slots are kernel-zeroed on first
    // access; we only need to reset variable fields between calls.
    ev->cgroup_id      = cgroup_id;
    ev->ts             = bpf_ktime_get_ns();
    ev->tgid           = tgid;
    ev->ppid           = 0;
    ev->argv_count     = 0;
    ev->argv_total_len = 0;
    ev->argv_truncated = 0;
    ev->path_truncated = 0;

    // ── Look up parent PPID from process_tree_map ──────────────────────────
    struct lineage_key lkey = { .cgroup_id = cgroup_id, .tgid = tgid, .pad = 0 };
    struct lineage_entry *lentry = bpf_map_lookup_elem(&process_tree_map, &lkey);
    if (lentry) {
        ev->ppid = lentry->ppid;
    }

    // ── Capture executable path ────────────────────────────────────────────
    long path_ret = bpf_probe_read_user_str(ev->path, EXEC_PATH_LEN, ctx->filename);
    if (path_ret < 0) {
        path_ret = 0;
    } else if (path_ret >= EXEC_PATH_LEN) {
        ev->path_truncated = 1;
    }

    // ── Capture argv (bounded, verifier-safe) ─────────────────────────────
    // Verifier proof: break when pos >= MAX_TOTAL_LEN - MAX_ARG_LEN.
    //   → In non-break path: pos < MAX_TOTAL_LEN - MAX_ARG_LEN = 1920.
    //   → room = MAX_ARG_LEN = 128 (compile-time constant, not variable).
    //   → pos + room < 1920 + 128 = 2048 = MAX_TOTAL_LEN. In bounds ✓
    // Using variable room triggered verifier's independent interval analysis
    // on pos and room separately, losing the correlation pos+room≤MAX_TOTAL_LEN.
    u32 pos  = 0;
    u32 argc = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        // Break before write: verifier knows pos < MAX_TOTAL_LEN - MAX_ARG_LEN
        if (pos >= MAX_TOTAL_LEN - MAX_ARG_LEN) {
            ev->argv_truncated = 1;
            break;
        }

        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp),
                                (const char *const *)(ctx->argv) + i) < 0 || !argp) {
            break;
        }

        // Fixed room = MAX_ARG_LEN: verifier sees constant, not range.
        long slen = bpf_probe_read_user_str(ev->argv + pos, MAX_ARG_LEN, argp);
        if (slen <= 0) break;

        pos += (u32)slen;
        // Mask resets verifier's range for pos each iteration: pos ∈ [0, MAX_TOTAL_LEN-1]
        pos &= (MAX_TOTAL_LEN - 1);
        argc++;
    }
    ev->argv_count     = argc;
    ev->argv_total_len = pos;

    // ── Upsert into process_tree_map ──────────────────────────────────────
    // exec.c is now the sole writer of process_tree_map (no separate fork hook).
    // We upsert: if an entry exists (populated by a previous fork-tracking
    // mechanism), update comm + comm_final; otherwise create a new entry.
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    if (lentry) {
        // Entry exists: update comm to the real executable name
        __builtin_memcpy(lentry->comm, comm, 16);
        lentry->comm_final = 1;
        bpf_map_update_elem(&process_tree_map, &lkey, lentry, BPF_ANY);
    } else {
        // No existing entry: create one from scratch
        struct lineage_entry new_entry = {};
        new_entry.ppid       = 0;  // unknown without fork hook; resolved later if needed
        new_entry.cgroup_id  = cgroup_id;
        new_entry.fork_ts    = ev->ts;
        new_entry.comm_final = 1;
        __builtin_memcpy(new_entry.comm, comm, 16);
        bpf_map_update_elem(&process_tree_map, &lkey, &new_entry, BPF_ANY);
    }

    // ── Copy scratch to ring buffer ────────────────────────────────────────
    // bpf_ringbuf_output copies from scratch without needing a reservation slot.
    // This is safe because exec_scratch is per-CPU (no concurrent writes on same CPU).
    bpf_ringbuf_output(&exec_events, ev, sizeof(*ev), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
