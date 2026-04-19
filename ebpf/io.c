// SPDX-License-Identifier: GPL-2.0
// M3: Disk I/O & File System Access
//
// Tracepoint layouts verified against kernel format files:
//   /sys/kernel/debug/tracing/events/block/block_rq_issue/format
//   /sys/kernel/debug/tracing/events/block/block_rq_complete/format
//
// Two bugs fixed from original version:
//   BUG 1 - Struct padding: `sector` is at offset 16, not offset 12.
//            There are 4 bytes of implicit padding after `dev` (offset 8, size 4).
//   BUG 2 - `rwbs` is char[10] not char[8] on this kernel.
//            Reading rwbs[0] for R/W detection still works once offset is correct.
//
// Maps:
//   bio_start_map   (scratch: (dev<<32|sector) → bio_scratch, deleted on complete)
//   io_stats_map    (output:  cgroup_id → io_stats)
//   file_events     (ring buffer: file open events via sys_enter_openat)

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

struct bio_scratch {
    u64 cgroup_id;
    u64 issue_ts;
    u32 rwflag;  // 1=write/discard, 0=read
    u32 bytes;
};

struct io_stats {
    u64 read_bytes;
    u64 write_bytes;
    u64 read_ios;
    u64 write_ios;
    u64 read_latency_ns;
    u64 write_latency_ns;
};

struct file_event {
    u64 cgroup_id;
    u32 pid;
    u32 flags;
    char comm[16];
    char filename[128];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   u64);
    __type(value, struct bio_scratch);
    __uint(max_entries, 65536);
} bio_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   u64);             // cgroup_id
    __type(value, struct io_stats);
    __uint(max_entries, 1024);
} io_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} file_events SEC(".maps");

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

static __always_inline struct io_stats *get_or_create_io(u64 cgroup_id) {
    struct io_stats *s = bpf_map_lookup_elem(&io_stats_map, &cgroup_id);
    if (!s) {
        struct io_stats zero = {};
        bpf_map_update_elem(&io_stats_map, &cgroup_id, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&io_stats_map, &cgroup_id);
    }
    return s;
}

// ---------------------------------------------------------------------------
// tracepoint/block/block_rq_issue
//
// VERIFIED FORMAT (from /sys/kernel/debug/tracing/events/block/block_rq_issue/format):
//   offset:0  size:2  common_type
//   offset:2  size:1  common_flags
//   offset:3  size:1  common_preempt_count
//   offset:4  size:4  common_pid
//   offset:8  size:4  dev              ← dev_t
//   [4 bytes implicit padding for u64 alignment]
//   offset:16 size:8  sector           ← sector_t (u64)
//   offset:24 size:4  nr_sector
//   offset:28 size:4  bytes
//   offset:32 size:2  ioprio
//   offset:34 size:10 rwbs[10]
//   offset:44 size:16 comm[16]
// ---------------------------------------------------------------------------
struct block_rq_issue_args {
    unsigned short common_type;           // offset 0
    unsigned char  common_flags;          // offset 2
    unsigned char  common_preempt_count;  // offset 3
    int            common_pid;            // offset 4
    /* --- event-specific fields --- */
    unsigned int   dev;                   // offset 8  (dev_t, 4 bytes)
    unsigned int   __pad;                 // offset 12 (4 bytes padding for sector alignment)
    unsigned long  sector;                // offset 16 (sector_t = u64)
    unsigned int   nr_sector;             // offset 24
    unsigned int   bytes;                 // offset 28
    unsigned short ioprio;                // offset 32
    char           rwbs[10];              // offset 34 (NOTE: char[10], not char[8])
    char           comm[16];              // offset 44
};

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct block_rq_issue_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u64 ts        = bpf_ktime_get_ns();

    // 'W'=Write, 'D'=Discard → rwflag=1; 'R'/'S'/'F'=Read → rwflag=0
    u32 rwflag = (ctx->rwbs[0] == 'W' || ctx->rwbs[0] == 'D') ? 1 : 0;

    // Use (dev<<32 | low32(sector)) as scratch key — unique per request
    u64 scratch_key = ((u64)ctx->dev << 32) | (u64)(ctx->sector & 0xFFFFFFFF);

    u32 bytes = ctx->bytes ? ctx->bytes : (ctx->nr_sector * 512);

    struct bio_scratch sc = {
        .cgroup_id = cgroup_id,
        .issue_ts  = ts,
        .rwflag    = rwflag,
        .bytes     = bytes,
    };
    bpf_map_update_elem(&bio_start_map, &scratch_key, &sc, BPF_ANY);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/block/block_rq_complete
//
// VERIFIED FORMAT (from /sys/kernel/debug/tracing/events/block/block_rq_complete/format):
//   offset:0  size:2  common_type
//   offset:2  size:1  common_flags
//   offset:3  size:1  common_preempt_count
//   offset:4  size:4  common_pid
//   offset:8  size:4  dev
//   [4 bytes padding]
//   offset:16 size:8  sector
//   offset:24 size:4  nr_sector
//   offset:28 size:4  error
//   offset:32 size:2  ioprio
//   offset:34 size:10 rwbs[10]
// ---------------------------------------------------------------------------
struct block_rq_complete_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    unsigned int   dev;         // offset 8
    unsigned int   __pad;       // offset 12 — 4 bytes padding
    unsigned long  sector;      // offset 16
    unsigned int   nr_sector;   // offset 24
    int            error;       // offset 28
    unsigned short ioprio;      // offset 32
    char           rwbs[10];    // offset 34
};

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct block_rq_complete_args *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 scratch_key = ((u64)ctx->dev << 32) | (u64)(ctx->sector & 0xFFFFFFFF);

    struct bio_scratch *sc = bpf_map_lookup_elem(&bio_start_map, &scratch_key);
    if (!sc)
        return 0;

    // Skip errored I/O
    if (ctx->error != 0) {
        bpf_map_delete_elem(&bio_start_map, &scratch_key);
        return 0;
    }

    u64 cgroup_id = sc->cgroup_id;
    u64 latency   = ts - sc->issue_ts;
    u32 rwflag    = sc->rwflag;
    u32 bytes     = sc->bytes;

    bpf_map_delete_elem(&bio_start_map, &scratch_key);

    struct io_stats *s = get_or_create_io(cgroup_id);
    if (!s)
        return 0;

    if (rwflag) {
        __sync_fetch_and_add(&s->write_bytes, bytes);
        __sync_fetch_and_add(&s->write_ios, 1);
        __sync_fetch_and_add(&s->write_latency_ns, latency);
    } else {
        __sync_fetch_and_add(&s->read_bytes, bytes);
        __sync_fetch_and_add(&s->read_ios, 1);
        __sync_fetch_and_add(&s->read_latency_ns, latency);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/syscalls/sys_enter_openat
// ---------------------------------------------------------------------------
struct sys_enter_openat_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    long           dfd;
    const char    *filename;   // user-space pointer
    long           flags;
    long           mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct sys_enter_openat_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    struct file_event *ev = bpf_ringbuf_reserve(&file_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->cgroup_id = cgroup_id;
    ev->pid       = bpf_get_current_pid_tgid() >> 32;
    ev->flags     = (u32)ctx->flags;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    long ret = bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), ctx->filename);
    if (ret <= 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
