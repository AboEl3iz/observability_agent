package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
	"ebpf/pkg/event"
	"ebpf/pkg/lineage"
)

// ─── Loaders (mirrors cmd/observer/main.go) ───────────────────────────────────

const bpfPinPath = "/sys/fs/bpf/ebpf-agent"

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
		coll.Close()
		closeLinks(links)
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
	var links []link.Link

	// 1. Attach OOM mark_victim (mandatory for OOM tracking)
	oomProg, ok := coll.Programs["trace_oom_mark_victim"]
	if !ok {
		coll.Close()
		return nil, nil, fmt.Errorf("trace_oom_mark_victim program not found")
	}
	oomLnk, err := link.Tracepoint("oom", "mark_victim", oomProg, nil)
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("attaching oom/mark_victim: %w", err)
	}
	links = append(links, oomLnk)
	log.Info("probe attached", "tracepoint", "oom/mark_victim")

	// 2. Attach page_fault_user (best-effort / non-fatal)
	pfProg, ok := coll.Programs["trace_page_fault_user"]
	if ok {
		pfLnk, err := link.Tracepoint("exceptions", "page_fault_user", pfProg, nil)
		if err != nil {
			log.Warn("exceptions/page_fault_user tracepoint unavailable — page fault tracking disabled", "err", err)
		} else {
			links = append(links, pfLnk)
			log.Info("probe attached", "tracepoint", "exceptions/page_fault_user")
		}
	}
	pfMap, ok := coll.Maps["page_fault_map"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("page_fault_map not found")
	}
	oomMap, ok := coll.Maps["oom_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("oom_events map not found")
	}
	memColl, err := collector.NewMemoryCollector(pfMap, oomMap, resolver, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
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
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("io_stats_map not found")
	}
	fileMap, ok := coll.Maps["file_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("file_events map not found")
	}
	ioColl, err := collector.NewIoCollector(ioMap, fileMap, resolver, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
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
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("conn_stats_map not found")
	}
	tcpRBMap, ok := coll.Maps["tcp_event_rb"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("tcp_event_rb map not found")
	}
	netColl, err := collector.NewNetworkCollector(connMap, tcpRBMap, resolver, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
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
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("syscall_stats_map not found")
	}
	rbMap, ok := coll.Maps["slow_syscall_rb"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("slow_syscall_rb map not found")
	}
	sysColl, err := collector.NewSyscallCollector(statsMap, rbMap, resolver, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
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

// ─── Phase 1 loader ───────────────────────────────────────────────────────────

func loadLineage(
	objPath string,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.LineageCollector, []link.Link, *ebpf.Map, error) {
	log.Info("loading Phase 1 Lineage BPF object", "path", objPath)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new collection: %w", err)
	}

	probes := []struct{ cat, ev, prog string }{
		{"sched", "sched_process_fork", "trace_lineage_fork"},
		{"sched", "sched_process_exit", "trace_lineage_exit"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, nil, err
	}

	forkRBMap, ok := coll.Maps["process_fork_rb"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, fmt.Errorf("process_fork_rb not found")
	}
	treeMap, ok := coll.Maps["process_tree_map"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, fmt.Errorf("process_tree_map not found")
	}

	// Pin process_tree_map to BPF filesystem for cross-module sharing.
	// Other BPF collections (exec, dns, privesc, escape) will receive this map
	// via ebpf.CollectionOptions.MapReplacer.
	if err := os.MkdirAll(bpfPinPath, 0700); err != nil {
		log.Warn("failed to create BPF pin path", "path", bpfPinPath, "err", err)
	} else {
		pinFile := filepath.Join(bpfPinPath, "process_tree_map")
		// Remove stale pin from previous run if present
		_ = os.Remove(pinFile)
		if err := treeMap.Pin(pinFile); err != nil {
			log.Warn("failed to pin process_tree_map — cross-module sharing via in-process map ref",
				"err", err)
		} else {
			log.Info("process_tree_map pinned", "path", pinFile)
		}
	}

	linColl, err := collector.NewLineageCollector(forkRBMap, treeMap, resolver, writer, bootOffset, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, err
	}

	log.Info("Phase 1 Lineage probes attached", "count", len(links))
	return linColl, links, treeMap, nil
}

// ─── loadSecurityModule: shared helper for Phases 2–5 ────────────────────────
// Loads a BPF collection and injects the shared process_tree_map via MapReplacer.

func loadSecurityBPF(
	objPath string,
	sharedTreeMap *ebpf.Map,
	log *slog.Logger,
) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"process_tree_map": sharedTreeMap,
		},
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("new collection with map replacer: %w", err)
	}
	return coll, nil
}

// ─── Phase 2 loader ───────────────────────────────────────────────────────────

// loadExecWithColl loads exec.o without MapReplacements (exec.c owns
// process_tree_map). Returns the raw collection so Phase 1 can extract
// process_tree_map. Caller must defer rawColl.Close().
func loadExecWithColl(
	objPath string,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.ExecCollector, []link.Link, *ebpf.Collection, error) {
	log.Info("loading Phase 2 Exec BPF object", "path", objPath)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new collection: %w", err)
	}

	probes := []struct{ cat, ev, prog string }{
		{"syscalls", "sys_enter_execve", "trace_exec"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, nil, err
	}

	execRBMap, ok := coll.Maps["exec_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, fmt.Errorf("exec_events map not found")
	}

	execColl, err := collector.NewExecCollector(execRBMap, nil, resolver, writer, bootOffset, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, err
	}
	// Return coll so loadLineageFromExec can access process_tree_map
	return execColl, links, coll, nil
}

// loadLineageFromExec extracts process_tree_map from the exec collection,
// pins it for sharing with dns/privesc/escape, and wraps it in a LineageCollector.
func loadLineageFromExec(
	execColl *ebpf.Collection,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.LineageCollector, *ebpf.Map, error) {
	treeMap, ok := execColl.Maps["process_tree_map"]
	if !ok {
		return nil, nil, fmt.Errorf("process_tree_map not in exec.o — run 'make bpf'")
	}

	if err := os.MkdirAll(bpfPinPath, 0700); err == nil {
		pinFile := filepath.Join(bpfPinPath, "process_tree_map")
		_ = os.Remove(pinFile)
		if err := treeMap.Pin(pinFile); err != nil {
			log.Warn("process_tree_map pin failed", "err", err)
		} else {
			log.Info("process_tree_map pinned", "path", pinFile)
		}
	}

	linColl, err := collector.NewLineageCollector(nil, treeMap, resolver, writer, bootOffset, log)
	if err != nil {
		return nil, nil, err
	}
	return linColl, treeMap, nil
}

// ─── Phase 3 loader ───────────────────────────────────────────────────────────

func loadDNS(
	objPath string,
	lookup lineage.LineageLookup,
	sharedTreeMap *ebpf.Map,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.DnsCollector, []link.Link, error) {
	log.Info("loading Phase 3 DNS BPF object", "path", objPath)
	coll, err := loadSecurityBPF(objPath, sharedTreeMap, log)
	if err != nil {
		return nil, nil, err
	}

	probes := []struct{ cat, ev, prog string }{
		// Path A + B: sendto — emits DNS event on entry (sys_exit EPERM on this kernel)
		{"syscalls", "sys_enter_sendto", "trace_dns_send"},
		{"syscalls", "sys_enter_sendmsg", "trace_dns_sendmsg"},
		{"syscalls", "sys_enter_sendmmsg", "trace_dns_sendmmsg"},
		{"syscalls", "sys_enter_write", "trace_dns_write"},
		// Path B (musl/busybox): connect() tracking for addr=NULL sendto
		{"syscalls", "sys_enter_connect", "trace_dns_connect"},
		// Cleanup: remove connected_dns_socks entry when fd is closed
		{"syscalls", "sys_enter_close", "trace_dns_close"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}

	dnsRBMap, ok := coll.Maps["dns_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("dns_events map not found")
	}

	dnsColl, err := collector.NewDnsCollector(dnsRBMap, lookup, resolver, writer, bootOffset, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
		return nil, nil, err
	}
	return dnsColl, links, nil
}

// ─── Phase 4 loader ───────────────────────────────────────────────────────────

func loadPrivEsc(
	objPath string,
	lookup lineage.LineageLookup,
	sharedTreeMap *ebpf.Map,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.PrivEscCollector, []link.Link, bool, error) {
	log.Info("loading Phase 4 PrivEsc BPF object", "path", objPath)
	coll, err := loadSecurityBPF(objPath, sharedTreeMap, log)
	if err != nil {
		return nil, nil, false, err
	}

	// Baseline tracepoints (stable ABI — always attach)
	probes := []struct{ cat, ev, prog string }{
		{"syscalls", "sys_enter_setuid", "trace_setuid"},
		{"syscalls", "sys_enter_setgid", "trace_setgid"},
		{"syscalls", "sys_enter_ptrace", "trace_ptrace"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, false, err
	}

	// Best-effort kprobe: cap_capable (Q3 — graceful degradation)
	// Attach failure is logged as a warning; agent continues without it.
	capKprobeAvailable := false
	if prog, ok := coll.Programs["kprobe_cap_capable"]; ok {
		if lnk, err := link.Kprobe("cap_capable", prog, nil); err != nil {
			log.Warn("cap_capable kprobe unavailable — privilege cap detection disabled",
				"err", err,
				"note", "may be blocked by kernel lockdown mode or missing symbol")
		} else {
			links = append(links, lnk)
			capKprobeAvailable = true
			log.Info("cap_capable kprobe attached")
		}
	}

	privescRBMap, ok := coll.Maps["privesc_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, false, fmt.Errorf("privesc_events map not found")
	}

	privColl, err := collector.NewPrivEscCollector(privescRBMap, lookup, resolver, writer, bootOffset, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
		return nil, nil, false, err
	}
	privColl.CapKprobeAvailable = capKprobeAvailable
	return privColl, links, capKprobeAvailable, nil
}

// ─── Phase 5 loader ───────────────────────────────────────────────────────────

func loadEscape(
	objPath string,
	lookup lineage.LineageLookup,
	sharedTreeMap *ebpf.Map,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.EscapeCollector, []link.Link, error) {
	log.Info("loading Phase 5 Escape BPF object", "path", objPath)
	coll, err := loadSecurityBPF(objPath, sharedTreeMap, log)
	if err != nil {
		return nil, nil, err
	}

	probes := []struct{ cat, ev, prog string }{
		{"syscalls", "sys_enter_mount", "trace_mount"},
		{"syscalls", "sys_enter_unshare", "trace_unshare"},
		{"syscalls", "sys_enter_pivot_root", "trace_pivot_root"},
	}
	links, err := attachProbes(coll, probes, log)
	if err != nil {
		coll.Close()
		return nil, nil, err
	}

	escapeRBMap, ok := coll.Maps["escape_events"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, fmt.Errorf("escape_events map not found")
	}

	escapeColl, err := collector.NewEscapeCollector(escapeRBMap, lookup, resolver, writer, bootOffset, log)
	if err != nil {
		coll.Close()
		closeLinks(links)
		return nil, nil, err
	}
	return escapeColl, links, nil
}

// ─── displayConfig carries display-time filtering options ────────────────────

type displayConfig struct {
	containersOnly bool
	topN           int
}

// isContainer returns true if the name looks like a Docker or containerd container.
// Docker containers: "docker:xxxxxxxxxxxx"
// containerd/k8s:   "cri:xxxxxxxxxxxx"
func isContainer(name string) bool {
	if strings.HasPrefix(name, "docker:") || strings.HasPrefix(name, "cri:") || strings.HasPrefix(name, "k8s:") || strings.HasPrefix(name, "cgroup:") {
		return true
	}
	// Kubernetes pod container names are formatted as "namespace/pod/container"
	if strings.Count(name, "/") == 2 {
		return true
	}
	return false
}
