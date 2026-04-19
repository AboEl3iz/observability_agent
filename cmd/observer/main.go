// eBPF Container Observability Agent — cmd/observer/main.go
//
// M0 + M1 + M2 + M3 + M4:
//   M0 — Cgroup scoping (resolver)
//   M1 — CPU & Thread observability  (cpu.o)
//   M2 — Memory & OOM Kill Root Cause (memory.o)
//   M3 — Disk I/O & File System Access (io.o)
//   M4 — Network Connection Tracking  (network.o)
//
// Usage:
//
//	sudo ./observer [flags]
//
// Flags:
//
//	--interval 2s              poll interval
//	--cpu-bpf  ebpf/cpu.o      CPU BPF object (M1)
//	--mem-bpf  ebpf/memory.o   Memory BPF object (M2)
//	--io-bpf   ebpf/io.o       I/O BPF object (M3)
//	--net-bpf  ebpf/network.o  Network BPF object (M4)
//	--containers-only          show only Docker/containerd containers
//	--show-files               stream file open events to stderr (M3)
//	--show-tcp                 stream TCP state transitions to stderr (M4)
//	--top N                    limit each table to the top N rows (0 = all)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
)

func main() {
	interval       := flag.Duration("interval", 2*time.Second, "poll interval")
	cpuBPF        := flag.String("cpu-bpf", "ebpf/cpu.o", "CPU BPF object (M1)")
	memBPF        := flag.String("mem-bpf", "ebpf/memory.o", "Memory BPF object (M2)")
	ioBPF         := flag.String("io-bpf", "ebpf/io.o", "I/O BPF object (M3)")
	netBPF        := flag.String("net-bpf", "ebpf/network.o", "Network BPF object (M4)")
	containersOnly := flag.Bool("containers-only", false, "show only Docker/containerd containers")
	showFiles      := flag.Bool("show-files", false, "stream file open events to stderr (M3)")
	showTCP        := flag.Bool("show-tcp", false, "stream TCP state transitions to stderr (M4)")
	topN           := flag.Int("top", 0, "limit each table to top N rows (0 = all)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// ── M0: cgroup resolver ────────────────────────────────────────────────
	resolver, err := cgroup.NewResolver()
	if err != nil {
		logger.Warn("cgroup resolver init failed — IDs only", "err", err)
		resolver = &cgroup.Resolver{}
	}

	// ── M1: CPU (cpu.o) ───────────────────────────────────────────────────
	cpuColl, cpuLinks, err := loadCPU(*cpuBPF, resolver, logger)
	if err != nil {
		logger.Error("M1 CPU init failed", "err", err)
		os.Exit(1)
	}
	defer closeLinks(cpuLinks)

	// ── M2: Memory (memory.o) ─────────────────────────────────────────────
	memColl, memLinks, err := loadMemory(*memBPF, resolver, logger)
	if err != nil {
		logger.Warn("M2 Memory init failed — memory metrics disabled", "err", err)
	}
	if memColl != nil {
		defer memColl.Close()
	}
	defer closeLinks(memLinks)

	// ── M3: I/O (io.o) ────────────────────────────────────────────────────
	ioColl, ioLinks, err := loadIO(*ioBPF, resolver, logger)
	if err != nil {
		logger.Warn("M3 I/O init failed — I/O metrics disabled", "err", err)
	}
	if ioColl != nil {
		defer ioColl.Close()
	}
	defer closeLinks(ioLinks)

	// ── M4: Network (network.o) ───────────────────────────────────────────
	netColl, netLinks, err := loadNetwork(*netBPF, resolver, logger)
	if err != nil {
		logger.Warn("M4 Network init failed — TCP metrics disabled", "err", err)
	}
	if netColl != nil {
		defer netColl.Close()
	}
	defer closeLinks(netLinks)

	// ── Graceful shutdown ─────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	filter := "all cgroups"
	if *containersOnly {
		filter = "containers only (docker: / cri:)"
	}
	logger.Info("observer running — press Ctrl+C to stop",
		"interval", *interval,
		"filter", filter,
		"M1_cpu", cpuColl != nil,
		"M2_mem", memColl != nil,
		"M3_io", ioColl != nil,
		"M4_net", netColl != nil,
	)
	fmt.Println()

	cfg := displayConfig{
		containersOnly: *containersOnly,
		topN:           *topN,
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down gracefully")
			return
		case <-ticker.C:
			printCpuTable(cpuColl, logger, cfg)

			if memColl != nil {
				printMemTable(memColl, logger, cfg)
				drainOOMEvents(memColl, logger)
			}

			if ioColl != nil {
				printIOTable(ioColl, logger, cfg)
				if *showFiles {
					drainFileEvents(ioColl, logger, cfg)
				}
			}

			if netColl != nil {
				printNetTable(netColl, logger, cfg)
				if *showTCP {
					drainTCPEvents(netColl, logger, cfg)
				}
			}
		}
	}
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
	return strings.HasPrefix(name, "docker:") || strings.HasPrefix(name, "cri:")
}

// ─── M1 loader ───────────────────────────────────────────────────────────────

func loadCPU(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.CpuCollector, []link.Link, error) {
	log.Info("loading M1 CPU BPF object", "path", objPath)
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

	log.Info("M1 CPU probes attached", "count", len(links))
	return collector.NewCpuCollector(cpuMap, resolver), links, nil
}

// ─── M2 loader ───────────────────────────────────────────────────────────────

func loadMemory(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.MemoryCollector, []link.Link, error) {
	log.Info("loading M2 Memory BPF object", "path", objPath)
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

	log.Info("M2 Memory probes attached", "count", len(links))
	return memColl, links, nil
}

// ─── M3 loader ───────────────────────────────────────────────────────────────

func loadIO(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.IoCollector, []link.Link, error) {
	log.Info("loading M3 I/O BPF object", "path", objPath)
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

	log.Info("M3 I/O probes attached", "count", len(links))
	return ioColl, links, nil
}

// ─── Generic probe attacher ───────────────────────────────────────────────────

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

// ─── Display helpers ──────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func applyTop[T any](s []T, n int) []T {
	if n > 0 && len(s) > n {
		return s[:n]
	}
	return s
}

func printCpuTable(c *collector.CpuCollector, log *slog.Logger, cfg displayConfig) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("CPU collect error", "err", err)
		return
	}

	// Sort by CPU time descending
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].CPUSeconds > samples[j].CPUSeconds
	})

	// Filter to containers only if requested
	if cfg.containersOnly {
		filtered := samples[:0]
		for _, s := range samples {
			if isContainer(s.ContainerName) {
				filtered = append(filtered, s)
			}
		}
		samples = filtered
	}

	samples = applyTop(samples, cfg.topN)

	now := time.Now().Format("15:04:05")
	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M1: CPU Observer  [%s]                                             ║\n", now)
	fmt.Printf("╠══════════════════════════╦════════════╦═══════════════╦══════════╦═══════╣\n")
	fmt.Printf("║ Container                ║ CPU (s/Δt) ║ RunQ lat (ms) ║ ctx sw/s ║ thrds ║\n")
	fmt.Printf("╠══════════════════════════╬════════════╬═══════════════╬══════════╬═══════╣\n")
	if len(samples) == 0 {
		fmt.Printf("║ (no container activity — start a Docker container to see data here)       ║\n")
	}
	for _, s := range samples {
		fmt.Printf("║ %-24s ║ %10.4f ║ %13.3f ║ %8.1f ║ %5d ║\n",
			truncate(s.ContainerName, 24),
			s.CPUSeconds,
			s.RunqLatencySeconds*1000,
			s.CtxSwitchesPerSec,
			s.ThreadCount,
		)
	}
	fmt.Printf("╚══════════════════════════╩════════════╩═══════════════╩══════════╩═══════╝\n")
}

func printMemTable(c *collector.MemoryCollector, log *slog.Logger, cfg displayConfig) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("Memory collect error", "err", err)
		return
	}

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].MemoryBytes > samples[j].MemoryBytes
	})

	if cfg.containersOnly {
		filtered := samples[:0]
		for _, s := range samples {
			if isContainer(s.ContainerName) {
				filtered = append(filtered, s)
			}
		}
		samples = filtered
	}

	samples = applyTop(samples, cfg.topN)

	now := time.Now().Format("15:04:05")
	fmt.Printf("\n╔══════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M2: Memory Observer  [%s]                                             ║\n", now)
	fmt.Printf("╠══════════════════════════╦═════════════╦═════════════╦══════════════════════╣\n")
	fmt.Printf("║ Container                ║  RSS (MB)   ║ Limit (MB)  ║ Page Faults/s        ║\n")
	fmt.Printf("╠══════════════════════════╬═════════════╬═════════════╬══════════════════════╣\n")
	if len(samples) == 0 {
		fmt.Printf("║ (no container activity — start a Docker container to see data here)          ║\n")
	}
	for _, s := range samples {
		rssMB := float64(s.MemoryBytes) / (1024 * 1024)
		limStr := "unlimited"
		if s.MemoryLimitBytes > 0 {
			limStr = fmt.Sprintf("%.1f", float64(s.MemoryLimitBytes)/(1024*1024))
		}
		fmt.Printf("║ %-24s ║ %11.2f ║ %11s ║ %20.1f ║\n",
			truncate(s.ContainerName, 24),
			rssMB,
			limStr,
			s.FaultsPerSec,
		)
	}
	fmt.Printf("╚══════════════════════════╩═════════════╩═════════════╩══════════════════════╝\n")
}

func drainOOMEvents(c *collector.MemoryCollector, log *slog.Logger) {
	events, err := c.ReadOOMEvents()
	if err != nil {
		log.Error("OOM event read error", "err", err)
		return
	}
	for _, ev := range events {
		rssKB := ev.Pages * 4
		log.Error("🔴 OOM KILL DETECTED",
			"container", ev.ContainerName,
			"victim_pid", ev.VictimPID,
			"comm", ev.Comm,
			"rss_kb", rssKB,
			"memory_limit_mb", ev.MemoryLimitBytes/(1024*1024),
			"memory_current_mb", ev.MemoryBytes/(1024*1024),
			"swap_bytes", ev.SwapBytes,
			"oom_score_adj", ev.OOMScoreAdj,
		)
	}
}

func printIOTable(c *collector.IoCollector, log *slog.Logger, cfg displayConfig) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("I/O collect error", "err", err)
		return
	}

	sort.Slice(samples, func(i, j int) bool {
		return (samples[i].ReadBytesPerSec + samples[i].WriteBytesPerSec) >
			(samples[j].ReadBytesPerSec + samples[j].WriteBytesPerSec)
	})

	if cfg.containersOnly {
		filtered := samples[:0]
		for _, s := range samples {
			if isContainer(s.ContainerName) {
				filtered = append(filtered, s)
			}
		}
		samples = filtered
	}

	samples = applyTop(samples, cfg.topN)

	now := time.Now().Format("15:04:05")
	fmt.Printf("\n╔════════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M3: I/O Observer  [%s]                                                      ║\n", now)
	fmt.Printf("╠══════════════════════════╦══════════════╦══════════════╦══════════╦════════════╣\n")
	fmt.Printf("║ Container                ║  Read KB/s   ║ Write KB/s   ║ R lat ms ║ W lat ms  ║\n")
	fmt.Printf("╠══════════════════════════╬══════════════╬══════════════╬══════════╬════════════╣\n")
	if len(samples) == 0 {
		fmt.Printf("║ (no container I/O activity — run a container with disk I/O to see data)           ║\n")
	}
	for _, s := range samples {
		fmt.Printf("║ %-24s ║ %12.2f ║ %12.2f ║ %8.2f ║ %9.2f ║\n",
			truncate(s.ContainerName, 24),
			s.ReadBytesPerSec/1024,
			s.WriteBytesPerSec/1024,
			s.AvgReadLatencyMs,
			s.AvgWriteLatencyMs,
		)
	}
	fmt.Printf("╚══════════════════════════╩══════════════╩══════════════╩══════════╩════════════╝\n")
}

func drainFileEvents(c *collector.IoCollector, log *slog.Logger, cfg displayConfig) {
	events, err := c.ReadFileEvents()
	if err != nil {
		log.Error("file event read error", "err", err)
		return
	}
	for _, ev := range events {
		if cfg.containersOnly && !isContainer(ev.ContainerName) {
			continue
		}
		log.Info("file open",
			"container", ev.ContainerName,
			"pid", ev.PID,
			"comm", ev.Comm,
			"flags", fmt.Sprintf("0x%x", ev.Flags),
			"file", ev.Filename,
		)
	}
}

// ─── M4 loader ───────────────────────────────────────────────────────────────

func loadNetwork(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.NetworkCollector, []link.Link, error) {
	log.Info("loading M4 Network BPF object", "path", objPath)
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

	log.Info("M4 Network probes attached", "count", len(links))
	return netColl, links, nil
}

// ─── M4 display ───────────────────────────────────────────────────────────────

func printNetTable(c *collector.NetworkCollector, log *slog.Logger, cfg displayConfig) {
	summaries, err := c.CollectSummary()
	if err != nil {
		log.Error("Network collect error", "err", err)
		return
	}

	// Sort by active flows descending
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ActiveFlows > summaries[j].ActiveFlows
	})

	if cfg.containersOnly {
		filtered := summaries[:0]
		for _, s := range summaries {
			if isContainer(s.ContainerName) {
				filtered = append(filtered, s)
			}
		}
		summaries = filtered
	}

	summaries = applyTop(summaries, cfg.topN)

	now := time.Now().Format("15:04:05")
	fmt.Printf("\n╔════════════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M4: Network Observer  [%s]                                                      ║\n", now)
	fmt.Printf("╠══════════════════════════╦═══════╦════════╦══════════╦═══════════╦══════════════╣\n")
	fmt.Printf("║ Container                ║ Flows ║ ESTABL ║ TIM_WAIT ║ CLO_WAIT  ║ Retransmits  ║\n")
	fmt.Printf("╠══════════════════════════╬═══════╬════════╬══════════╬═══════════╬══════════════╣\n")
	if len(summaries) == 0 {
		fmt.Printf("║ (no TCP activity — run a container that makes network connections)                   ║\n")
	}
	for _, s := range summaries {
		fmt.Printf("║ %-24s ║ %5d ║ %6d ║ %8d ║ %9d ║ %12d ║\n",
			truncate(s.ContainerName, 24),
			s.ActiveFlows,
			s.Established,
			s.TimeWait,
			s.CloseWait,
			s.TotalRetransmits,
		)
	}
	fmt.Printf("╚══════════════════════════╩═══════╩════════╩══════════╩═══════════╩══════════════╝\n")
}

func drainTCPEvents(c *collector.NetworkCollector, log *slog.Logger, cfg displayConfig) {
	events, err := c.ReadTCPEvents()
	if err != nil {
		log.Error("TCP event read error", "err", err)
		return
	}
	for _, ev := range events {
		if cfg.containersOnly && !isContainer(ev.ContainerName) {
			continue
		}
		log.Info("TCP state change",
			"container", ev.ContainerName,
			"src", fmt.Sprintf("%s:%d", ev.Saddr, ev.Sport),
			"dst", fmt.Sprintf("%s:%d", ev.Daddr, ev.Dport),
			"old", ev.OldState,
			"new", ev.NewState,
		)
	}
}
