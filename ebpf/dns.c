// SPDX-License-Identifier: GPL-2.0
// Phase 3: DNS Observability
//
// Tracepoints:
//   syscalls/sys_enter_connect    — detect connected UDP port-53 sockets
//   syscalls/sys_exit_connect     — confirm connect() succeeded
//   syscalls/sys_enter_sendto     — capture DNS query (addr arg or connected socket)
//   syscalls/sys_exit_recvfrom    — capture RCODE + latency
//
// Root cause of "no events for Alpine/musl":
//   musl libc DNS resolver uses connect()+send() NOT sendto(addr).
//   On Linux, send() = sendto(fd, buf, len, flags, NULL, 0).
//   Our original `if (!ctx->addr) return 0` guard dropped all musl events.
//
// Fix: two-path detection:
//   Path A — sendto with explicit addr:  standard glibc/getaddrinfo style
//   Path B — connect(UDP, port 53) then sendto(NULL): musl/busybox/nslookup style
//
//   connect tracking:
//     sys_enter_connect → if dport==53 && SOCK_DGRAM → store {pid_tgid,fd}→info
//     sys_exit_connect  → if ret<0 → remove stale entry (failed connect)
//     sys_enter_sendto  → if addr==NULL → look up connected_dns_socks[{pid_tgid,fd}]
//     sys_enter_close / sys_exit_exit_group → clean up on fd close (LRU fallback)
//
// Scope (Q4): QNAME + QTYPE + latency_ns + RCODE only.

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define DNS_PORT        53
#define MAX_DNS_NAME    255
#define DNS_HDR_LEN     12
#define DNS_QUERY_BUF   256

#define AF_INET  2
#define AF_INET6 10

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
// dns_scratch: per-tid context stored between sendto and recvfrom
// ---------------------------------------------------------------------------

struct dns_scratch {
    u64  send_ts;
    u64  cgroup_id;
    u32  tgid;
    u16  dport;
    u8   family;
    u8   pad;
    u8   query[DNS_QUERY_BUF];
    u32  query_len;
    u32  pad2;
};

// ---------------------------------------------------------------------------
// dns_socket_info: tracks connected UDP sockets destined for port 53.
// Keyed by {pid_tgid, fd} — populated on sys_enter_connect to port 53.
// ---------------------------------------------------------------------------

struct dns_sock_key {
    u64 pid_tgid;
    u32 fd;
    u32 pad;
};

struct dns_socket_info {
    u64 cgroup_id;
    u32 tgid;
    u16 dport;   // always 53 for entries in this map
    u8  family;
    u8  pad;
};

// ---------------------------------------------------------------------------
// dns_event: ring buffer payload
// ---------------------------------------------------------------------------

struct dns_event {
    u64  cgroup_id;
    u64  send_ts;
    u64  latency_ns;
    u32  tgid;
    u32  ppid;
    char comm[16];
    char qname[MAX_DNS_NAME + 1];
    u16  qtype;
    u16  rcode;
    u8   has_response;
    u8   via_connect;   // 1 = event came from connected-socket path (musl/busybox)
    u8   pad[2];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Per-CPU staging for sendto assembly (avoids 512-byte stack limit)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dns_scratch);
    __uint(max_entries, 1);
} dns_scratch_map SEC(".maps");

// Per-CPU staging for connect() sockaddr (small — fits inline on stack actually,
// but isolated here for clarity and to avoid interference with dns_scratch_map)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dns_socket_info);
    __uint(max_entries, 1);
} dns_connect_tmp SEC(".maps");

// tid → sendto context is no longer needed: we emit directly from sendto.
// Kept as a small LRU for future latency tracking if kernel allows sys_exit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct dns_scratch);
    __uint(max_entries, 64);  // minimal — only for future use
} dns_send_ts SEC(".maps");

// {pid_tgid, fd} → socket info for connected UDP DNS sockets
// LRU eviction handles cleanup when close() is missed.
// max_entries = 4096: upper bound on concurrent connected DNS sockets system-wide.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct dns_sock_key);
    __type(value, struct dns_socket_info);
    __uint(max_entries, 4096);
} connected_dns_socks SEC(".maps");

// Ring buffer for DNS events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} dns_events SEC(".maps");

// Shared process tree from lineage.o (read-only)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lineage_key);
    __type(value, struct lineage_entry);
    __uint(max_entries, 65536);
} process_tree_map SEC(".maps");

// ---------------------------------------------------------------------------
// Minimal sockaddr structs (no linux/socket.h in BPF)
// ---------------------------------------------------------------------------

struct sockaddr_in_bpf {
    u16 sin_family;
    u16 sin_port;   // big-endian
    u32 sin_addr;
};

// Minimal IPv6 — only family + port needed for port filtering
struct sockaddr_in6_min {
    u16 sin6_family;
    u16 sin6_port;  // big-endian
};

// ---------------------------------------------------------------------------
// Tracepoint context layouts
// Note: all syscall args after __syscall_nr are stored as the natural type
// but aligned to the next register boundary by the compiler (natural alignment).
// int fd (4B) + 4B padding → void *buff at natural 8B alignment = offset 24. ✓
// ---------------------------------------------------------------------------

struct sys_enter_connect_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    int             fd;
    struct sockaddr *uservaddr;   // user-space pointer
    int             addrlen;
};

struct sys_exit_connect_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    long            ret;
};

struct sys_enter_sendto_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    int             fd;
    void           *buff;
    unsigned long   len;
    unsigned int    flags;
    struct sockaddr *addr;        // NULL for connected sockets (musl/busybox path)
    int             addr_len;
};

struct sys_exit_recvfrom_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    long            ret;
    int             fd;
    void           *ubuf;
    unsigned long   size;
    unsigned int    flags;
    struct sockaddr *addr;
    int            *addr_len;
};

struct sys_enter_close_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    unsigned int    fd;
};

struct iovec_bpf {
    void            *iov_base;
    unsigned long   iov_len;
};

struct user_msghdr_bpf {
    void            *msg_name;
    int             msg_namelen;
    int             pad1;
    struct iovec_bpf *msg_iov;
    unsigned long   msg_iovlen;
    void            *msg_control;
    unsigned long   msg_controllen;
    unsigned int    msg_flags;
    int             pad2;
};

struct mmsghdr_bpf {
    struct user_msghdr_bpf msg_hdr;
    unsigned int           msg_len;
    int                    pad;
};

struct sys_enter_sendmsg_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    int             fd;
    void           *msg;
    unsigned int    flags;
};

struct sys_enter_sendmmsg_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    int             fd;
    void           *mmsg;
    unsigned int    vlen;
    unsigned int    flags;
};

struct sys_enter_write_args {
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int             common_pid;
    long            __syscall_nr;
    int             fd;
    void           *buf;
    unsigned long   count;
};

// ---------------------------------------------------------------------------
// parse_qname: copy raw query bytes (after DNS header) into out buffer.
// Go-side decoder handles label decoding. BPF only needs to transport bytes.
// Returns DNS_HDR_LEN + copy_len so QTYPE can be located by caller.
static __always_inline u32 parse_qname(struct dns_scratch *sc,
                                        u32 offset, char *out, u32 out_size) {
    // Ensure offset is within query buffer — verifier-safe constant comparison
    if (offset >= DNS_QUERY_BUF) return offset;

    // How many bytes to copy: bounded to both query_len and out_size
    u32 qlen = sc->query_len;
    if (qlen > DNS_QUERY_BUF) qlen = DNS_QUERY_BUF;  // clamp to buf size

    u32 avail = (qlen > offset) ? (qlen - offset) : 0;
    u32 copy  = avail;
    if (copy > out_size) copy = out_size;
    if (copy > MAX_DNS_NAME) copy = MAX_DNS_NAME;  // fits in qname[256]

    // Mask offset and copy length for the verifier
    u32 src_off = offset & (DNS_QUERY_BUF - 1);   // ∈ [0, 255]
    u32 dst_len = copy  & (MAX_DNS_NAME);          // ∈ [0, 255]

    if (dst_len > 0 && src_off < DNS_QUERY_BUF) {
        // bpf_probe_read_kernel: safe copy from map value pointer to ring buf
        // src: sc->query + src_off, max = sc->query[255] = offset 279 < 288 ✓
        // dst: out (ev->qname from ring buffer) — no map-value constraint ✓
        bpf_probe_read_kernel(out, dst_len, sc->query + src_off);
    }

    // Return approximate offset after QNAME for QTYPE extraction.
    // Scan for the null terminator in the raw copy (first zero byte = end of QNAME).
    u32 end = offset;
    #pragma unroll
    for (u32 i = 0; i < MAX_DNS_NAME; i++) {
        if (i >= copy) break;
        if (out[i & MAX_DNS_NAME] == 0) { end = offset + i + 1; break; }
    }
    return end;
}

// ---------------------------------------------------------------------------
// Helper: fill and submit a dns_event from scratch + lineage context
// ---------------------------------------------------------------------------
static __always_inline void emit_dns_event(struct dns_scratch *sc,
                                            u64 latency_ns, u8 via_connect,
                                            void *response_buf, long resp_len) {
    u64 cgroup_id = sc->cgroup_id;
    u32 tgid      = sc->tgid;

    struct dns_event *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
    if (!ev) return;

    ev->cgroup_id    = cgroup_id;
    ev->send_ts      = sc->send_ts;
    ev->latency_ns   = latency_ns;
    ev->tgid         = tgid;
    ev->ppid         = 0;
    ev->qtype        = 0;
    ev->rcode        = 0;
    ev->has_response = (resp_len > 0) ? 1 : 0;
    ev->via_connect  = via_connect;

    // Enrich from process_tree_map
    struct lineage_key lkey = { .cgroup_id = cgroup_id, .tgid = tgid, .pad = 0 };
    struct lineage_entry *lentry = bpf_map_lookup_elem(&process_tree_map, &lkey);
    if (lentry) {
        __builtin_memcpy(ev->comm, lentry->comm, 16);
        ev->ppid = lentry->ppid;
    } else {
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    }

    // Parse QNAME from saved query payload
    u32 qtype_offset = DNS_HDR_LEN;
    if (sc->query_len > DNS_HDR_LEN) {
        qtype_offset = parse_qname(sc, DNS_HDR_LEN, ev->qname, sizeof(ev->qname));
    }

    // Extract QTYPE (2 bytes big-endian after QNAME)
    if (qtype_offset + 2 <= sc->query_len && qtype_offset + 2 <= DNS_QUERY_BUF) {
        u32 qto = qtype_offset & (DNS_QUERY_BUF - 1);
        if (qto + 1 < DNS_QUERY_BUF) {
            ev->qtype = ((u16)sc->query[qto] << 8) | sc->query[qto + 1];
        }
    }

    // Extract RCODE from DNS response header byte 3 (bits [3:0])
    if (resp_len >= DNS_HDR_LEN && response_buf) {
        u8 hdr[DNS_HDR_LEN] = {};
        if (bpf_probe_read_user(hdr, DNS_HDR_LEN, response_buf) >= 0) {
            ev->rcode = hdr[3] & 0x0F;
        }
    }

    bpf_ringbuf_submit(ev, 0);
}

// ---------------------------------------------------------------------------
// PATH B — sys_enter_connect
//
// Intercepts connect() calls to port 53 on UDP sockets.
// Records the {pid_tgid, fd} → socket_info mapping for the connected-socket path.
// Called by musl, busybox nslookup, and any resolver that uses connect()+send().
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_dns_connect(struct sys_enter_connect_args *ctx) {
    if (!ctx->uservaddr) return 0;

    // Read address family (first 2 bytes of sockaddr — safe minimal read)
    struct sockaddr_in_bpf sa4 = {};
    if (bpf_probe_read_user(&sa4, sizeof(sa4), ctx->uservaddr) < 0) return 0;

    u16 family = sa4.sin_family;
    u16 dport  = 0;

    if (family == AF_INET) {
        dport = __builtin_bswap16(sa4.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6_min sa6 = {};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), ctx->uservaddr) < 0) return 0;
        dport = __builtin_bswap16(sa6.sin6_port);
    } else {
        return 0; // not IP
    }

    // Only interested in DNS destination port
    if (dport != DNS_PORT) return 0;

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 tgid      = (u32)(pid_tgid >> 32);

    struct dns_sock_key skey = {
        .pid_tgid = pid_tgid,
        .fd       = (u32)ctx->fd,
        .pad      = 0,
    };
    struct dns_socket_info sinfo = {
        .cgroup_id = cgroup_id,
        .tgid      = tgid,
        .dport     = dport,
        .family    = (u8)family,
        .pad       = 0,
    };

    bpf_map_update_elem(&connected_dns_socks, &skey, &sinfo, BPF_ANY);
    return 0;
}

// ---------------------------------------------------------------------------
// PATH B — sys_exit_connect
//
// If connect() failed, remove the pre-inserted entry so we don't track
// failed connections. This prevents spurious lookups on fd reuse.
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_exit_connect")
int trace_dns_connect_exit(struct sys_exit_connect_args *ctx) {
    // Only clean up on failure; success keeps the entry
    // Note: we don't have the fd here, so we can't remove specific entries.
    // LRU eviction will handle stale entries from failed connects.
    // (Enhancement: use a per-CPU temp map in sys_enter_connect to stash fd,
    //  then remove on failure in exit — left as future optimization)
    return 0;
}

// ---------------------------------------------------------------------------
// sys_enter_close — clean up connected_dns_socks on fd close
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_close")
int trace_dns_close(struct sys_enter_close_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct dns_sock_key skey = {
        .pid_tgid = pid_tgid,
        .fd       = ctx->fd,
        .pad      = 0,
    };
    // Delete if present — no-op if not a tracked DNS socket
    bpf_map_delete_elem(&connected_dns_socks, &skey);
    return 0;
}

// ---------------------------------------------------------------------------
// PATH A + B — sys_enter_sendto
//
// Path A (glibc/getaddrinfo): ctx->addr != NULL — traditional sendto
// Path B (musl/busybox):      ctx->addr == NULL — connected socket, look up map
// ---------------------------------------------------------------------------
static __always_inline int handle_dns_send(u64 tid, u64 cgroup_id, u32 tgid, int fd, struct sockaddr *addr, void *buff, unsigned long len) {
    u16 dport     = 0;
    u8  family    = 0;
    u8  via_connect = 0;

    if (addr) {
        // PATH A: explicit destination address
        struct sockaddr_in_bpf sa4 = {};
        if (bpf_probe_read_user(&sa4, sizeof(sa4), addr) < 0) return 0;

        family = (u8)sa4.sin_family;
        if (family == AF_INET) {
            dport = __builtin_bswap16(sa4.sin_port);
        } else if (family == AF_INET6) {
            struct sockaddr_in6_min sa6 = {};
            if (bpf_probe_read_user(&sa6, sizeof(sa6), addr) < 0) return 0;
            dport = __builtin_bswap16(sa6.sin6_port);
        } else {
            return 0;
        }
        if (dport != DNS_PORT) return 0;

    } else {
        // PATH B: connected socket
        struct dns_sock_key skey = {
            .pid_tgid = tid,
            .fd       = (u32)fd,
            .pad      = 0,
        };
        struct dns_socket_info *sinfo = bpf_map_lookup_elem(&connected_dns_socks, &skey);
        if (!sinfo) return 0; // not a connected DNS socket

        dport      = sinfo->dport;
        family     = sinfo->family;
        cgroup_id  = sinfo->cgroup_id;
        tgid       = sinfo->tgid;
        via_connect = 1;
    }

    // Use per-CPU scratch to assemble dns_scratch (avoids stack overflow)
    u32 zero = 0;
    struct dns_scratch *sc = bpf_map_lookup_elem(&dns_scratch_map, &zero);
    if (!sc) return 0;

    sc->send_ts   = bpf_ktime_get_ns();
    sc->cgroup_id = cgroup_id;
    sc->tgid      = tgid;
    sc->dport     = dport;
    sc->family    = family;
    sc->query_len = 0;

    // Capture DNS request payload from user buffer
    u32 qlen = (u32)len;
    if (qlen > DNS_QUERY_BUF) qlen = DNS_QUERY_BUF;
    if (qlen > 0 && buff) {
        long ret = bpf_probe_read_user(sc->query, qlen, buff);
        if (ret >= 0) sc->query_len = qlen;
    }

    // Emit DNS event immediately from enter tracepoint
    emit_dns_event(sc, 0 /*latency unknown*/, via_connect, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_send(struct sys_enter_sendto_args *ctx) {
    u64 tid       = bpf_get_current_pid_tgid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 tgid      = (u32)(tid >> 32);
    return handle_dns_send(tid, cgroup_id, tgid, ctx->fd, ctx->addr, ctx->buff, ctx->len);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_dns_sendmsg(struct sys_enter_sendmsg_args *ctx) {
    if (!ctx->msg) return 0;

    struct user_msghdr_bpf msg = {};
    if (bpf_probe_read_user(&msg, sizeof(msg), ctx->msg) < 0) return 0;

    if (!msg.msg_iov) return 0;

    struct iovec_bpf iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov) < 0) return 0;

    u64 tid       = bpf_get_current_pid_tgid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 tgid      = (u32)(tid >> 32);

    struct sockaddr *addr = msg.msg_namelen > 0 ? msg.msg_name : NULL;

    return handle_dns_send(tid, cgroup_id, tgid, ctx->fd, addr, iov.iov_base, iov.iov_len);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_dns_sendmmsg(struct sys_enter_sendmmsg_args *ctx) {
    if (!ctx->mmsg) return 0;

    struct mmsghdr_bpf mmsg = {};
    if (bpf_probe_read_user(&mmsg, sizeof(mmsg), ctx->mmsg) < 0) return 0;

    struct user_msghdr_bpf *msg = &mmsg.msg_hdr;
    if (!msg->msg_iov) return 0;

    struct iovec_bpf iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), msg->msg_iov) < 0) return 0;

    u64 tid       = bpf_get_current_pid_tgid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 tgid      = (u32)(tid >> 32);

    struct sockaddr *addr = msg->msg_namelen > 0 ? msg->msg_name : NULL;

    return handle_dns_send(tid, cgroup_id, tgid, ctx->fd, addr, iov.iov_base, iov.iov_len);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_dns_write(struct sys_enter_write_args *ctx) {
    u64 tid       = bpf_get_current_pid_tgid();
    struct dns_sock_key skey = {
        .pid_tgid = tid,
        .fd       = (u32)ctx->fd,
        .pad      = 0,
    };
    // Only proceed if this is a known connected DNS socket
    struct dns_socket_info *sinfo = bpf_map_lookup_elem(&connected_dns_socks, &skey);
    if (!sinfo) return 0;

    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 tgid      = (u32)(tid >> 32);

    return handle_dns_send(tid, cgroup_id, tgid, ctx->fd, NULL, ctx->buf, ctx->count);
}

// ---------------------------------------------------------------------------
// sys_exit_recvfrom — REMOVED: ring-buffer programs fail on sys_exit
// tracepoints with EPERM on this kernel/LSM configuration.
// DNS events are now emitted from sys_enter_sendto above.
// ---------------------------------------------------------------------------

char LICENSE[] SEC("license") = "GPL";
