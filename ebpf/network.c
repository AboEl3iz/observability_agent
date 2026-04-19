// SPDX-License-Identifier: GPL-2.0
// M4: Network Connection Tracking (TCP state machine + retransmits)
//
// Tracepoint layouts byte-verified against kernel format files:
//   /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
//   /sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/format
//
// Maps:
//   conn_stats_map   (hash: conn_key → conn_stats — per-flow counters)
//   tcp_event_rb     (ring buffer: TCP state transition events)

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

// ---------------------------------------------------------------------------
// TCP state constants (from Linux net/tcp_states.h)
// ---------------------------------------------------------------------------
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11
#define TCP_NEW_SYN_RECV 12

#define AF_INET          2
#define AF_INET6         10
#define IPPROTO_TCP      6

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

// Per-flow key (IPv4 only for now; IPv6 future work)
struct conn_key {
    u64 cgroup_id;
    u32 saddr;       // source IPv4
    u32 daddr;       // dest IPv4
    u16 sport;
    u16 dport;
    u32 __pad;       // explicit padding for map key alignment
};

// Per-flow counters
struct conn_stats {
    u32 state;         // latest TCP state (TCP_ESTABLISHED etc.)
    u32 retransmits;   // cumulative retransmits for this flow
    u64 first_seen_ns; // ktime_ns when ESTABLISHED first seen
    u64 last_seen_ns;  // ktime_ns of last state transition
};

// TCP state event shipped to userspace via ring buffer
struct tcp_event {
    u64 cgroup_id;
    u64 ts_ns;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;      // AF_INET or AF_INET6
    u16 __pad;
    int oldstate;
    int newstate;
    // IPv6 addresses (populated when family == AF_INET6)
    u8  saddr_v6[16];
    u8  daddr_v6[16];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Connection stats: per cgroup+flow counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct conn_key);
    __type(value, struct conn_stats);
    __uint(max_entries, 65536);
} conn_stats_map SEC(".maps");

// Ring buffer for TCP state events (4 MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} tcp_event_rb SEC(".maps");

// ---------------------------------------------------------------------------
// tracepoint/sock/inet_sock_set_state
//
// VERIFIED FORMAT (byte offsets from kernel format file):
//   offset:0   size:2  common_type
//   offset:2   size:1  common_flags
//   offset:3   size:1  common_preempt_count
//   offset:4   size:4  common_pid
//   offset:8   size:8  skaddr        (const void *)
//   offset:16  size:4  oldstate      (int)
//   offset:20  size:4  newstate      (int)
//   offset:24  size:2  sport         (__u16)
//   offset:26  size:2  dport         (__u16)
//   offset:28  size:2  family        (__u16)
//   offset:30  size:2  protocol      (__u16)
//   offset:32  size:4  saddr[4]      (__u8[4])
//   offset:36  size:4  daddr[4]      (__u8[4])
//   offset:40  size:16 saddr_v6[16]  (__u8[16])
//   offset:56  size:16 daddr_v6[16]  (__u8[16])
// ---------------------------------------------------------------------------
struct inet_sock_set_state_args {
    unsigned short common_type;           // offset 0
    unsigned char  common_flags;          // offset 2
    unsigned char  common_preempt_count;  // offset 3
    int            common_pid;            // offset 4
    const void    *skaddr;                // offset 8  (8 bytes)
    int            oldstate;              // offset 16
    int            newstate;              // offset 20
    u16            sport;                 // offset 24
    u16            dport;                 // offset 26
    u16            family;                // offset 28
    u16            protocol;              // offset 30
    u8             saddr[4];             // offset 32
    u8             daddr[4];             // offset 36
    u8             saddr_v6[16];         // offset 40
    u8             daddr_v6[16];         // offset 56
};

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
    // Only track TCP
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    u64 cgroup_id = bpf_get_current_cgroup_id();
    u64 ts        = bpf_ktime_get_ns();

    // Build conn_key using IPv4 (saddr/daddr are stored as 4×u8 in the tp)
    u32 saddr = *(__u32 *)ctx->saddr;
    u32 daddr = *(__u32 *)ctx->daddr;

    struct conn_key k = {
        .cgroup_id = cgroup_id,
        .saddr     = saddr,
        .daddr     = daddr,
        .sport     = ctx->sport,
        .dport     = ctx->dport,
    };

    // Upsert conn_stats
    struct conn_stats *s = bpf_map_lookup_elem(&conn_stats_map, &k);
    if (!s) {
        struct conn_stats zero = {
            .state        = (u32)ctx->newstate,
            .retransmits  = 0,
            .first_seen_ns = ts,
            .last_seen_ns  = ts,
        };
        bpf_map_update_elem(&conn_stats_map, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&conn_stats_map, &k);
        if (!s)
            goto emit_event;
    }
    s->state       = (u32)ctx->newstate;
    s->last_seen_ns = ts;

    // Remove closed flows from the map to prevent unbounded growth
    if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_TIME_WAIT) {
        bpf_map_delete_elem(&conn_stats_map, &k);
    }

emit_event:;
    // Ship every state transition to userspace via ring buffer
    struct tcp_event *ev = bpf_ringbuf_reserve(&tcp_event_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->cgroup_id = cgroup_id;
    ev->ts_ns     = ts;
    ev->saddr     = saddr;
    ev->daddr     = daddr;
    ev->sport     = ctx->sport;
    ev->dport     = ctx->dport;
    ev->family    = ctx->family;
    ev->oldstate  = ctx->oldstate;
    ev->newstate  = ctx->newstate;

    // Copy v6 addresses for completeness (zeroed for IPv4)
    __builtin_memcpy(ev->saddr_v6, ctx->saddr_v6, 16);
    __builtin_memcpy(ev->daddr_v6, ctx->daddr_v6, 16);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint/tcp/tcp_retransmit_skb
//
// VERIFIED FORMAT (byte offsets from kernel format file):
//   offset:0   size:2  common_type
//   offset:2   size:1  common_flags
//   offset:3   size:1  common_preempt_count
//   offset:4   size:4  common_pid
//   offset:8   size:8  skbaddr       (const void *)
//   offset:16  size:8  skaddr        (const void *)
//   offset:24  size:4  state         (int)
//   offset:28  size:2  sport         (__u16)
//   offset:30  size:2  dport         (__u16)
//   offset:32  size:2  family        (__u16)
//   offset:34  size:4  saddr[4]      (__u8[4])
//   offset:38  size:4  daddr[4]      (__u8[4])
//   offset:42  size:16 saddr_v6[16]  (__u8[16])
//   offset:58  size:16 daddr_v6[16]  (__u8[16])
//   offset:76  size:4  err           (int)
// ---------------------------------------------------------------------------
struct tcp_retransmit_skb_args {
    unsigned short common_type;           // offset 0
    unsigned char  common_flags;          // offset 2
    unsigned char  common_preempt_count;  // offset 3
    int            common_pid;            // offset 4
    const void    *skbaddr;               // offset 8
    const void    *skaddr;                // offset 16
    int            state;                 // offset 24
    u16            sport;                 // offset 28
    u16            dport;                 // offset 30
    u16            family;                // offset 32
    u8             saddr[4];             // offset 34
    u8             daddr[4];             // offset 38
    u8             saddr_v6[16];         // offset 42
    u8             daddr_v6[16];         // offset 58
    int            err;                  // offset 76
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct tcp_retransmit_skb_args *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    u32 saddr = *(__u32 *)ctx->saddr;
    u32 daddr = *(__u32 *)ctx->daddr;

    struct conn_key k = {
        .cgroup_id = cgroup_id,
        .saddr     = saddr,
        .daddr     = daddr,
        .sport     = ctx->sport,
        .dport     = ctx->dport,
    };

    struct conn_stats *s = bpf_map_lookup_elem(&conn_stats_map, &k);
    if (s) {
        __sync_fetch_and_add(&s->retransmits, 1);
    } else {
        // First-seen retransmit (no ESTABLISHED event yet or already closed)
        struct conn_stats zero = {
            .state       = (u32)ctx->state,
            .retransmits = 1,
        };
        bpf_map_update_elem(&conn_stats_map, &k, &zero, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
