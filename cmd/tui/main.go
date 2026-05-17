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
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"ebpf/internal/tui/app"
	"ebpf/internal/tui/config"
	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
	"ebpf/pkg/graph"
)

func main() {
	// ── CLI flags (backward compatible with original) ─────────────────────────
	intervalFlag := flag.Duration("interval", 0, "data poll interval (overrides config)")
	cpuBPF := flag.String("cpu-bpf", "ebpf/cpu.o", "CPU BPF object (M1)")
	memBPF := flag.String("mem-bpf", "ebpf/memory.o", "Memory BPF object (M2)")
	ioBPF := flag.String("io-bpf", "ebpf/io.o", "I/O BPF object (M3)")
	netBPF := flag.String("net-bpf", "ebpf/network.o", "Network BPF object (M4)")
	sysBPF := flag.String("sys-bpf", "ebpf/syscall.o", "Syscall BPF object (M6)")
	_ = flag.String("lineage-bpf", "ebpf/lineage.o", "Lineage BPF object (Phase 1) - ignored in favor of exec extraction")
	execBPF := flag.String("exec-bpf", "ebpf/exec.o", "Exec BPF object (Phase 2)")
	dnsBPF := flag.String("dns-bpf", "ebpf/dns.o", "DNS BPF object (Phase 3)")
	privescBPF := flag.String("privesc-bpf", "ebpf/privesc.o", "PrivEsc BPF object (Phase 4)")
	escapeBPF := flag.String("escape-bpf", "ebpf/escape.o", "Escape BPF object (Phase 5)")
	containersOnly := flag.Bool("containers-only", false, "show only Docker/containerd containers")
	showFiles := flag.Bool("show-files", false, "stream file open events (M3)")
	showTCP := flag.Bool("show-tcp", false, "stream TCP state transitions (M4)")
	showSlowSys := flag.Bool("show-slow-sys", false, "stream slow syscall events (M6)")
	topN := flag.Int("top", 0, "limit each table to top N rows (0 = all)")
	demo := flag.Bool("demo", false, "run with simulated data (no BPF required)")
	themeName := flag.String("theme", "", "theme: github-dark|nord|gruvbox|tokyo-night|catppuccin|solarized")
	flag.Parse()

	// ── Config: load from file, then apply CLI overrides ──────────────────────
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load warning: %v\n", err)
	}
	if *intervalFlag > 0 {
		cfg.DataIntervalMs = int(*intervalFlag / time.Millisecond)
	}
	if *containersOnly {
		cfg.ContainersOnly = true
	}
	if *showFiles {
		cfg.ShowFiles = true
	}
	if *showTCP {
		cfg.ShowTCP = true
	}
	if *showSlowSys {
		cfg.ShowSlowSys = true
	}
	if *topN > 0 {
		cfg.TopN = *topN
	}
	if *themeName != "" {
		cfg.Theme = *themeName
	}

	// ── Logger (tui.log in temp directory to avoid scrambling BubbleTea terminal and polluting workspace) ─
	logPath := filepath.Join(os.TempDir(), "tui.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		logFile = os.Stderr
	}
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// ── Remove RLIMIT_MEMLOCK before ANY BPF map/program allocation ─────────
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("failed to remove memlock rlimit — BPF map allocation may fail", "err", err)
	}

	// ── Collectors ────────────────────────────────────────────────────────────
	var (
		cpuColl *collector.CpuCollector
		memColl *collector.MemoryCollector
		ioColl  *collector.IoCollector
		netColl *collector.NetworkCollector
		sysColl *collector.SyscallCollector

		// Security (Phases 1-5)
		linColl     *collector.LineageCollector
		execColl    *collector.ExecCollector
		dnsColl     *collector.DnsCollector
		privEscColl *collector.PrivEscCollector
		escapeColl  *collector.EscapeCollector
		secWriter   = &app.TuiSecurityWriter{}

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

		memColl, links, err = loadMemory(*memBPF, resolver, logger)
		if err != nil {
			logger.Warn("M2 Memory load failed — OOM and page faults disabled", "err", err)
		} else {
			allLinks = append(allLinks, links...)
		}

		ioColl, links, err = loadIO(*ioBPF, resolver, logger)
		if err != nil {
			logger.Warn("M3 I/O load failed — I/O metrics disabled", "err", err)
		} else {
			allLinks = append(allLinks, links...)
		}

		netColl, links, err = loadNetwork(*netBPF, resolver, logger)
		if err != nil {
			logger.Warn("M4 Network load failed — TCP metrics disabled", "err", err)
		} else {
			allLinks = append(allLinks, links...)
		}

		sysColl, links, err = loadSyscall(*sysBPF, resolver, logger)
		if err != nil {
			logger.Warn("M6 Syscall load failed — Syscall metrics disabled", "err", err)
		} else {
			allLinks = append(allLinks, links...)
		}

		// ── Phase 1-5 Security Loaders ──────────────────────────────────────────
		bootOffset, err := cgroup.BootTimeOffset()
		if err != nil {
			logger.Warn("failed to compute boot time offset", "err", err)
		}

		var execRawColl *ebpf.Collection
		execColl, links, execRawColl, err = loadExecWithColl(*execBPF, resolver, secWriter, bootOffset, logger)
		if err == nil {
			allLinks = append(allLinks, links...)
			defer execRawColl.Close()

			var treeMap *ebpf.Map
			linColl, treeMap, err = loadLineageFromExec(execRawColl, resolver, secWriter, bootOffset, logger)
			if err == nil {
				dnsColl, links, _ = loadDNS(*dnsBPF, linColl, treeMap, resolver, secWriter, bootOffset, logger)
				allLinks = append(allLinks, links...)

				var capKprobeAvailable bool
				privEscColl, links, capKprobeAvailable, _ = loadPrivEsc(*privescBPF, linColl, treeMap, resolver, secWriter, bootOffset, logger)
				allLinks = append(allLinks, links...)
				_ = capKprobeAvailable // ignoring for TUI

				escapeColl, links, _ = loadEscape(*escapeBPF, linColl, treeMap, resolver, secWriter, bootOffset, logger)
				allLinks = append(allLinks, links...)
			} else {
				logger.Warn("Lineage extraction from Exec failed", "err", err)
			}
		} else {
			logger.Warn("Exec BPF failed to load", "err", err)
		}

		defer closeLinks(allLinks)
	}

	// ProcessGraph — shared live process graph.
	procGraph := graph.New(graph.DefaultMaxNodes)

	colls := &app.CollectorSet{
		CPU:       cpuColl,
		Mem:       memColl,
		IO:        ioColl,
		Net:       netColl,
		Syscall:   sysColl,
		Lineage:   linColl,
		Exec:      execColl,
		DNS:       dnsColl,
		PrivEsc:   privEscColl,
		Escape:    escapeColl,
		SecWriter: secWriter,
		Graph:     procGraph,
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
