// eBPF Observer TUI — entry point.
//
// This file is intentionally thin.  All business logic lives in
// internal/tui/app and internal/tui/views.  The job here is:
//  1. Parse CLI flags (preserved from original).
//  2. Override config with CLI flags.
//  3. Load BPF collectors (reusing collectors.go, unchanged).
//  4. Hand off to app.New + tea.NewProgram.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf/link"

	"ebpf/internal/tui/app"
	"ebpf/internal/tui/config"
	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
)

func main() {
	// ── CLI flags (backward compatible with original) ─────────────────────────
	intervalFlag   := flag.Duration("interval", 0, "data poll interval (overrides config)")
	cpuBPF         := flag.String("cpu-bpf", "ebpf/cpu.o", "CPU BPF object (M1)")
	memBPF         := flag.String("mem-bpf", "ebpf/memory.o", "Memory BPF object (M2)")
	ioBPF          := flag.String("io-bpf", "ebpf/io.o", "I/O BPF object (M3)")
	netBPF         := flag.String("net-bpf", "ebpf/network.o", "Network BPF object (M4)")
	sysBPF         := flag.String("sys-bpf", "ebpf/syscall.o", "Syscall BPF object (M6)")
	containersOnly := flag.Bool("containers-only", false, "show only Docker/containerd containers")
	showFiles      := flag.Bool("show-files", false, "stream file open events (M3)")
	showTCP        := flag.Bool("show-tcp", false, "stream TCP state transitions (M4)")
	showSlowSys    := flag.Bool("show-slow-sys", false, "stream slow syscall events (M6)")
	topN           := flag.Int("top", 0, "limit each table to top N rows (0 = all)")
	demo           := flag.Bool("demo", false, "run with simulated data (no BPF required)")
	themeName      := flag.String("theme", "", "theme: github-dark|nord|gruvbox|tokyo-night|catppuccin|solarized")
	flag.Parse()

	// ── Config: load from file, then apply CLI overrides ──────────────────────
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load warning: %v\n", err)
	}
	if *intervalFlag > 0 {
		cfg.DataIntervalMs = int(*intervalFlag / time.Millisecond)
	}
	if *containersOnly { cfg.ContainersOnly = true }
	if *showFiles      { cfg.ShowFiles = true }
	if *showTCP        { cfg.ShowTCP = true }
	if *showSlowSys    { cfg.ShowSlowSys = true }
	if *topN > 0       { cfg.TopN = *topN }
	if *themeName != "" { cfg.Theme = *themeName }

	// ── Logger (stderr only; TUI owns stdout) ─────────────────────────────────
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// ── Collectors ────────────────────────────────────────────────────────────
	var (
		cpuColl *collector.CpuCollector
		memColl *collector.MemoryCollector
		ioColl  *collector.IoCollector
		netColl *collector.NetworkCollector
		sysColl *collector.SyscallCollector
		allLinks []link.Link
	)

	if !*demo {
		resolver, err := cgroup.NewResolver()
		if err != nil {
			logger.Warn("cgroup resolver init failed — IDs only", "err", err)
			resolver = &cgroup.Resolver{}
		}

		var links []link.Link
		cpuColl, links, err = loadCPU(*cpuBPF, resolver, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "M1 CPU init failed: %v\n  Tip: pass --demo for simulated data\n", err)
			os.Exit(1)
		}
		allLinks = append(allLinks, links...)

		memColl, links, _ = loadMemory(*memBPF, resolver, logger)
		allLinks = append(allLinks, links...)
		ioColl, links, _ = loadIO(*ioBPF, resolver, logger)
		allLinks = append(allLinks, links...)
		netColl, links, _ = loadNetwork(*netBPF, resolver, logger)
		allLinks = append(allLinks, links...)
		sysColl, links, _ = loadSyscall(*sysBPF, resolver, logger)
		allLinks = append(allLinks, links...)

		defer closeLinks(allLinks)
	}

	colls := &app.CollectorSet{
		CPU:     cpuColl,
		Mem:     memColl,
		IO:      ioColl,
		Net:     netColl,
		Syscall: sysColl,
	}

	// ── Launch TUI ────────────────────────────────────────────────────────────
	root := app.New(cfg, colls, *demo)
	p := tea.NewProgram(root,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}
}
