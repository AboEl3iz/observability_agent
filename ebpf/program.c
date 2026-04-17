// +build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u32 u32;
typedef __u64 u64;

struct proc_key {
    u32 pid;
    u32 tid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct proc_key);
    __type(value, u64);
    __uint(max_entries, 1024);
} syscall_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} ctx_switch_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

// syscall tracking
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct proc_key key = {};
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 *count, zero = 0;

    count = bpf_map_lookup_elem(&syscall_count, &key);
    if (!count) {
        bpf_map_update_elem(&syscall_count, &key, &zero, BPF_ANY);
        count = bpf_map_lookup_elem(&syscall_count, &key);
    }

    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

// context switch tracking
SEC("tracepoint/sched/sched_switch")
int trace_sched(void *ctx) {
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&ctx_switch_count, &key);

    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

// network packet tracking
SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive(void *ctx) {
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&packet_count, &key);

    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";