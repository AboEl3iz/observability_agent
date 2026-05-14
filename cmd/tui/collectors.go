package main

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
)

// ─── Loaders (mirrors cmd/observer/main.go) ───────────────────────────────────

func loadCPU(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.CpuCollector, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}
	probes := []struct{ cat, ev, prog string }{
		{"sched", "sched_switch", "trace_sched_switch"},
		{"sched", "sched_wakeup", "trace_sched_wakeup"},
		{"sched", "sched_process_fork", "trace_sched_fork"},
		{"sched", "sched_process_exit", "trace_sched_exit"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}
	cpuMap, ok := coll.Maps["cpu_stats_map"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("cpu_stats_map not found")
	}
	return collector.NewCpuCollector(cpuMap, resolver), links, nil
}

func loadMemory(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.MemoryCollector, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}
	probes := []struct{ cat, ev, prog string }{
		{"oom", "mark_victim", "trace_oom_mark_victim"},
		{"exceptions", "page_fault_user", "trace_page_fault_user"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}
	pfMap, ok := coll.Maps["page_fault_map"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("page_fault_map not found")
	}
	oomMap, ok := coll.Maps["oom_events"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("oom_events map not found")
	}
	memColl, err := collector.NewMemoryCollector(pfMap, oomMap, resolver, log)
	if err != nil {
		coll.Close(); closeLinks(links)
		return nil, nil, err
	}
	return memColl, links, nil
}

func loadIO(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.IoCollector, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}
	probes := []struct{ cat, ev, prog string }{
		{"block", "block_rq_issue", "trace_block_rq_issue"},
		{"block", "block_rq_complete", "trace_block_rq_complete"},
		{"syscalls", "sys_enter_openat", "trace_sys_enter_openat"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}
	ioMap, ok := coll.Maps["io_stats_map"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("io_stats_map not found")
	}
	fileMap, ok := coll.Maps["file_events"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("file_events map not found")
	}
	ioColl, err := collector.NewIoCollector(ioMap, fileMap, resolver, log)
	if err != nil {
		coll.Close(); closeLinks(links)
		return nil, nil, err
	}
	return ioColl, links, nil
}

func loadNetwork(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.NetworkCollector, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}
	probes := []struct{ cat, ev, prog string }{
		{"sock", "inet_sock_set_state", "trace_inet_sock_set_state"},
		{"tcp", "tcp_retransmit_skb", "trace_tcp_retransmit"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}
	connMap, ok := coll.Maps["conn_stats_map"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("conn_stats_map not found")
	}
	tcpRBMap, ok := coll.Maps["tcp_event_rb"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("tcp_event_rb map not found")
	}
	netColl, err := collector.NewNetworkCollector(connMap, tcpRBMap, resolver, log)
	if err != nil {
		coll.Close(); closeLinks(links)
		return nil, nil, err
	}
	return netColl, links, nil
}

func loadSyscall(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.SyscallCollector, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("new collection: %w", err)
	}
	probes := []struct{ cat, ev, prog string }{
		{"raw_syscalls", "sys_enter", "trace_sys_enter"},
		{"raw_syscalls", "sys_exit", "trace_sys_exit"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}
	statsMap, ok := coll.Maps["syscall_stats_map"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("syscall_stats_map not found")
	}
	rbMap, ok := coll.Maps["slow_syscall_rb"]
	if !ok {
		coll.Close(); closeLinks(links)
		return nil, nil, fmt.Errorf("slow_syscall_rb map not found")
	}
	sysColl, err := collector.NewSyscallCollector(statsMap, rbMap, resolver, log)
	if err != nil {
		coll.Close(); closeLinks(links)
		return nil, nil, err
	}
	return sysColl, links, nil
}

func attachProbes(coll *ebpf.Collection, probes []struct{ cat, ev, prog string }, log *slog.Logger) ([]link.Link, error) {
	var links []link.Link
	for _, p := range probes {
		prog, ok := coll.Programs[p.prog]
		if !ok {
			return links, fmt.Errorf("BPF program %q not found", p.prog)
		}
		lnk, err := link.Tracepoint(p.cat, p.ev, prog, nil)
		if err != nil {
			return links, fmt.Errorf("attaching %s/%s: %w", p.cat, p.ev, err)
		}
		log.Info("probe attached", "tracepoint", p.cat+"/"+p.ev)
		links = append(links, lnk)
	}
	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}


