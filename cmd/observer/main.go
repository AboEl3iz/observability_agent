// eBPF Container Observability Agent — cmd/observer/main.go
//
// M0 + M1 + M2 + M3 + M4 + M6:
//
//	M0 — Cgroup scoping (resolver)
//	M1 — CPU & Thread observability  (cpu.o)
//	M2 — Memory & OOM Kill Root Cause (memory.o)
//	M3 — Disk I/O & File System Access (io.o)
//	M4 — Network Connection Tracking  (network.o)
//	M6 — Syscall Latency Observability (syscall.o)
//
// Security Telemetry (Phase 1–5):
//
//	Phase 1 — Process Lineage Tracking     (lineage.o)
//	Phase 2 — Full Execve Argument Capture (exec.o)
//	Phase 3 — DNS Observability            (dns.o)
//	Phase 4 — Privilege Escalation         (privesc.o)
//	Phase 5 — Container Escape Indicators  (escape.o)
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
//	--sys-bpf  ebpf/syscall.o  Syscall BPF object (M6)
//	--lineage-bpf ebpf/lineage.o  Phase 1 lineage
//	--exec-bpf    ebpf/exec.o     Phase 2 execve capture
//	--dns-bpf     ebpf/dns.o      Phase 3 DNS
//	--privesc-bpf ebpf/privesc.o  Phase 4 privilege escalation
//	--escape-bpf  ebpf/escape.o   Phase 5 container escape
//	--containers-only          show only Docker/containerd containers
//	--show-files               stream file open events to stderr (M3)
//	--show-tcp                 stream TCP state transitions to stderr (M4)
//	--show-slow-sys            stream slow syscall events to stderr (M6)
//	--show-security            stream security events to stderr (Phase 1–5)
//	--top N                    limit each table to the top N rows (0 = all)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
	"ebpf/pkg/event"
	"ebpf/pkg/exporter"
	"ebpf/pkg/lineage"
)

// bpfPinPath is where process_tree_map is pinned for cross-module sharing.
// Other BPF collections (exec, dns, privesc, escape) receive it via MapReplacer.
const bpfPinPath = "/sys/fs/bpf/ebpf-agent"

func main() {
	interval := flag.Duration("interval", 2*time.Second, "poll interval")
	cpuBPF := flag.String("cpu-bpf", "ebpf/cpu.o", "CPU BPF object (M1)")
	memBPF := flag.String("mem-bpf", "ebpf/memory.o", "Memory BPF object (M2)")
	ioBPF := flag.String("io-bpf", "ebpf/io.o", "I/O BPF object (M3)")
	netBPF := flag.String("net-bpf", "ebpf/network.o", "Network BPF object (M4)")
	sysBPF := flag.String("sys-bpf", "ebpf/syscall.o", "Syscall BPF object (M6)")
	lineageBPF := flag.String("lineage-bpf", "", "Phase 1 Process Lineage BPF object")
	execBPF := flag.String("exec-bpf", "", "Phase 2 Execve Capture BPF object")
	dnsBPF := flag.String("dns-bpf", "", "Phase 3 DNS Observability BPF object")
	privescBPF := flag.String("privesc-bpf", "", "Phase 4 Privilege Escalation BPF object")
	escapeBPF := flag.String("escape-bpf", "", "Phase 5 Container Escape BPF object")
	containersOnly := flag.Bool("containers-only", false, "show only Docker/containerd containers")
	showFiles := flag.Bool("show-files", false, "stream file open events to stderr (M3)")
	showTCP := flag.Bool("show-tcp", false, "stream TCP state transitions to stderr (M4)")
	showSlowSys := flag.Bool("show-slow-sys", false, "stream slow syscall events to stderr (M6)")
	showSecurity := flag.Bool("show-security", false, "stream security events to stderr (Phase 1–5)")
	topN := flag.Int("top", 0, "limit each table to top N rows (0 = all)")
	k8sSupport := flag.Bool("kubernetes", false, "enable kubernetes support")
	flag.Parse()

	// Suppress unused warning if needed, actually we just parse it.
	_ = k8sSupport

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// ── Boot-time offset computation (requirement 1.8) ─────────────────────
	// Computed once at startup; passed to all security collectors.
	// wall_ns = bpf_ktime_get_ns() + bootOffset
	bootOffset, err := cgroup.BootTimeOffset()
	if err != nil {
		logger.Warn("failed to compute boot time offset — timestamps may be inaccurate",
			"err", err)
		bootOffset = 0
	}
	logger.Info("boot time offset computed", "offset_ns", bootOffset)

	// ── Remove RLIMIT_MEMLOCK before ANY BPF map/program allocation ─────────
	// Without this, ring buffers (8 MB each) and large LRU maps push the
	// process over the locked-memory limit, causing BPF_LINK_CREATE to fail
	// with EPERM even when running as root on kernels with low default limits.
	// cilium/ebpf rlimit.RemoveMemlock() sets RLIMIT_MEMLOCK = RLIM_INFINITY.
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("failed to remove memlock rlimit — BPF map allocation may fail",
			"err", err)
	}

	// ── Startup Kernel Feature Detection ──────────────────────────────────
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		logger.Warn("Kernel may not support Kprobe", "err", err)
	}
	if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
		logger.Warn("Kernel may not support TracePoint", "err", err)
	}
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		logger.Warn("Kernel may not support RingBuf (requires 5.8+)", "err", err)
	}

	// ── HTTP Server (Health) ──────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	go func() {
		logger.Info("Starting HTTP server", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error", "err", err)
		}
	}()

	promExporter := exporter.NewPrometheusExporter(prometheus.DefaultRegisterer)

	// ── M0: cgroup resolver ────────────────────────────────────────────────
	resolver, err := cgroup.NewResolver()
	if err != nil {
		logger.Warn("cgroup resolver init failed — IDs only", "err", err)
		resolver = &cgroup.Resolver{}
	}

	// ── M1: CPU (cpu.o) ───────────────────────────────────────────────────
	cpuColl, cpuLinks, cpuRawColl, err := loadCPU(*cpuBPF, resolver, logger)
	if err != nil {
		logger.Error("M1 CPU init failed", "err", err)
		os.Exit(1)
	}
	defer closeLinks(cpuLinks)
	if cpuRawColl != nil {
		defer cpuRawColl.Close()
	}

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

	// ── M6: Syscall (syscall.o) ───────────────────────────────────────────
	sysColl, sysLinks, err := loadSyscall(*sysBPF, resolver, logger)
	if err != nil {
		logger.Warn("M6 Syscall init failed — Syscall metrics disabled", "err", err)
	}
	if sysColl != nil {
		defer sysColl.Close()
	}
	defer closeLinks(sysLinks)

	// ── Security EventWriter ─────────────────────────────────────────────────
	// stderrSecurityWriter emits JSON events to stderr.
	// containerFilterWriter wraps it and drops events from non-container cgroups
	// when --containers-only is active.
	var secWriter event.SecurityEventWriter
	if *showSecurity {
		var base event.SecurityEventWriter = &stderrSecurityWriter{log: logger}
		if *containersOnly {
			base = &containerFilterWriter{inner: base}
		}
		secWriter = base
	}

	// Always wrap with Prometheus metrics even if not logging to stderr
	secWriter = &exporter.PrometheusSecurityEventWriter{
		Inner:    secWriter,
		Exporter: promExporter,
	}

	// ── Phase 2 → Phase 1: Exec loads first to source process_tree_map ────
	// exec.c (syscall tracepoint) can use ring buffers freely.
	// sched tracepoints cannot — so process_tree_map is owned by exec.c.
	// exec.c upserts on every execve; phases 3-5 read it for enrichment.
	var execColl *collector.ExecCollector
	var lineageColl *collector.LineageCollector
	var lineageTreeMap *ebpf.Map
	if *execBPF != "" {
		var execLinks []link.Link
		var execRawColl *ebpf.Collection
		execColl, execLinks, execRawColl, err = loadExecWithColl(
			*execBPF, resolver, secWriter, bootOffset, logger)
		if err != nil {
			logger.Warn("Phase 2 Exec init failed — exec capture + lineage disabled", "err", err)
		} else {
			defer execColl.Close()
			defer closeLinks(execLinks)
			if execRawColl != nil {
				defer execRawColl.Close()
			}
			logger.Info("Phase 2 Exec probes attached")

			// Phase 1: extract process_tree_map from exec collection
			if *lineageBPF != "" {
				lineageColl, lineageTreeMap, err = loadLineageFromExec(
					execRawColl, resolver, secWriter, bootOffset, logger)
				if err != nil {
					logger.Warn("Phase 1 Lineage init failed", "err", err)
				} else {
					defer lineageColl.Close()
					logger.Info("Phase 1 Lineage active (process_tree_map from exec.o)")
				}
			}
		}
	}

	// ── Phase 3: DNS (dns.o) ───────────────────────────────────────────────
	var dnsColl *collector.DnsCollector
	if *dnsBPF != "" && lineageTreeMap != nil {
		var dnsLinks []link.Link
		dnsColl, dnsLinks, err = loadDNS(
			*dnsBPF, lineageColl, lineageTreeMap, resolver, secWriter, bootOffset, logger)
		if err != nil {
			logger.Warn("Phase 3 DNS init failed — DNS observability disabled", "err", err)
		} else {
			defer dnsColl.Close()
			defer closeLinks(dnsLinks)
			logger.Info("Phase 3 DNS probes attached")
		}
	}

	// ── Phase 4: Privilege Escalation (privesc.o) ─────────────────────────
	var privescColl *collector.PrivEscCollector
	if *privescBPF != "" && lineageTreeMap != nil {
		var privescLinks []link.Link
		var capAvail bool
		privescColl, privescLinks, capAvail, err = loadPrivEsc(
			*privescBPF, lineageColl, lineageTreeMap, resolver, secWriter, bootOffset, logger)
		if err != nil {
			logger.Warn("Phase 4 PrivEsc init failed — privilege escalation detection disabled", "err", err)
		} else {
			defer privescColl.Close()
			defer closeLinks(privescLinks)
			logger.Info("Phase 4 PrivEsc probes attached",
				"cap_capable_kprobe", capAvail)
		}
	}

	// ── Phase 5: Container Escape (escape.o) ──────────────────────────────
	var escapeColl *collector.EscapeCollector
	if *escapeBPF != "" && lineageTreeMap != nil {
		var escapeLinks []link.Link
		escapeColl, escapeLinks, err = loadEscape(
			*escapeBPF, lineageColl, lineageTreeMap, resolver, secWriter, bootOffset, logger)
		if err != nil {
			logger.Warn("Phase 5 Escape init failed — container escape detection disabled", "err", err)
		} else {
			defer escapeColl.Close()
			defer closeLinks(escapeLinks)
			logger.Info("Phase 5 Escape probes attached")
		}
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("HTTP server shutdown error", "err", err)
		}
		// Clean up pinned BPF maps on shutdown
		_ = os.RemoveAll(bpfPinPath)
	}()

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
		"M6_sys", sysColl != nil,
		"P1_lineage", lineageColl != nil,
		"P2_exec", execColl != nil,
		"P3_dns", dnsColl != nil,
		"P4_privesc", privescColl != nil,
		"P5_escape", escapeColl != nil,
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
			printCpuTable(cpuColl, logger, cfg, promExporter)

			if memColl != nil {
				printMemTable(memColl, logger, cfg, promExporter)
				drainOOMEvents(memColl, logger, promExporter)
			}

			if ioColl != nil {
				printIOTable(ioColl, logger, cfg, promExporter)
				if *showFiles {
					drainFileEvents(ioColl, logger, cfg)
				}
			}

			if netColl != nil {
				printNetTable(netColl, logger, cfg, promExporter)
				if *showTCP {
					drainTCPEvents(netColl, logger, cfg)
				}
			}

			if sysColl != nil {
				printSyscallTable(sysColl, logger, cfg, promExporter)
				if *showSlowSys {
					drainSlowSyscallEvents(sysColl, logger, cfg)
				}
			}

			// Phase 1–5: drain security events every poll tick.
			// Events are emitted via secWriter (stderr JSON when --show-security).
			// Even when secWriter is nil, draining prevents ring buffer backpressure.
			if lineageColl != nil {
				if _, err := lineageColl.ReadForkEvents(); err != nil {
					logger.Error("lineage fork event read error", "err", err)
				}
			}
			if execColl != nil {
				if _, err := execColl.ReadExecEvents(); err != nil {
					logger.Error("exec event read error", "err", err)
				}
			}
			if dnsColl != nil {
				if _, err := dnsColl.ReadDNSEvents(); err != nil {
					logger.Error("dns event read error", "err", err)
				}
			}
			if privescColl != nil {
				if _, err := privescColl.ReadPrivEscEvents(); err != nil {
					logger.Error("privesc event read error", "err", err)
				}
			}
			if escapeColl != nil {
				if _, err := escapeColl.ReadEscapeEvents(); err != nil {
					logger.Error("escape event read error", "err", err)
				}
			}
		}
	}
}

// ─── stderrSecurityWriter ─────────────────────────────────────────────────────

// stderrSecurityWriter implements event.SecurityEventWriter by emitting
// JSON-formatted security events to stderr via slog.
// Future writers (TUI tab, file) implement the same interface without code changes.
type stderrSecurityWriter struct {
	log *slog.Logger
}

func (w *stderrSecurityWriter) Write(ev event.EventEnvelope) {
	data, err := json.Marshal(ev)
	if err != nil {
		w.log.Error("failed to marshal security event", "err", err)
		return
	}
	w.log.Info("🔐 security event", "event", string(data))
}

// ─── containerFilterWriter ─────────────────────────────────────────────────

// containerFilterWriter is a SecurityEventWriter that only passes through
// events originating from Docker or containerd containers, identified by the
// ContainerName field populated by each collector via the cgroup resolver.
// This enforces --containers-only semantics at the security event layer.
type containerFilterWriter struct {
	inner event.SecurityEventWriter
}

func (w *containerFilterWriter) Write(ev event.EventEnvelope) {
	// Drop events from non-container processes (host PID namespace, system daemons, etc.)
	if !isContainer(ev.ContainerName) {
		return
	}
	w.inner.Write(ev)
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
	if strings.HasPrefix(name, "docker:") || strings.HasPrefix(name, "cri:") || strings.HasPrefix(name, "k8s:") {
		return true
	}
	// Kubernetes pod container names are formatted as "namespace/pod/container"
	if strings.Count(name, "/") == 2 {
		return true
	}
	return false
}

// ─── M1 loader ───────────────────────────────────────────────────────────────

func loadCPU(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.CpuCollector, []link.Link, *ebpf.Collection, error) {
	log.Info("loading M1 CPU BPF object", "path", objPath)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new collection: %w", err)
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
		return nil, nil, nil, err
	}

	cpuMap, ok := coll.Maps["cpu_stats_map"]
	if !ok {
		coll.Close()
		closeLinks(links)
		return nil, nil, nil, fmt.Errorf("cpu_stats_map not found")
	}

	log.Info("M1 CPU probes attached", "count", len(links))
	// Return coll so Phase 1 (loadLineageFromCPU) can access process_tree_map
	// and process_fork_rb embedded in cpu.c. Caller must defer coll.Close().
	return collector.NewCpuCollector(cpuMap, resolver), links, coll, nil
}

// loadLineageFromCPU creates a LineageCollector from maps embedded in cpu.c.
// No new BPF programs or perf links — fork/exit tracking runs in cpu.c's
// existing sched_process_fork/exit handlers.
func loadLineageFromCPU(
	cpuColl *ebpf.Collection,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*collector.LineageCollector, *ebpf.Map, error) {
	forkRBMap, ok := cpuColl.Maps["process_fork_rb"]
	if !ok {
		return nil, nil, fmt.Errorf("process_fork_rb not found in cpu.o — run 'make bpf' to rebuild")
	}
	treeMap, ok := cpuColl.Maps["process_tree_map"]
	if !ok {
		return nil, nil, fmt.Errorf("process_tree_map not found in cpu.o — run 'make bpf' to rebuild")
	}

	// Pin process_tree_map so exec/dns/privesc/escape modules can share it
	if err := os.MkdirAll(bpfPinPath, 0700); err == nil {
		pinFile := filepath.Join(bpfPinPath, "process_tree_map")
		_ = os.Remove(pinFile)
		if err := treeMap.Pin(pinFile); err != nil {
			log.Warn("process_tree_map pin failed — in-process map ref used", "err", err)
		} else {
			log.Info("process_tree_map pinned", "path", pinFile)
		}
	}

	linColl, err := collector.NewLineageCollector(forkRBMap, treeMap, resolver, writer, bootOffset, log)
	if err != nil {
		return nil, nil, err
	}
	return linColl, treeMap, nil
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
	if strings.HasPrefix(s, "docker:") {
		s = s[7:]
	} else if strings.HasPrefix(s, "cri:") {
		s = s[4:]
	}

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

func printCpuTable(c *collector.CpuCollector, log *slog.Logger, cfg displayConfig, prom *exporter.PrometheusExporter) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("CPU collect error", "err", err)
		return
	}

	if prom != nil {
		prom.UpdateCPU(samples)
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

func printMemTable(c *collector.MemoryCollector, log *slog.Logger, cfg displayConfig, prom *exporter.PrometheusExporter) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("Memory collect error", "err", err)
		return
	}

	if prom != nil {
		prom.UpdateMemory(samples)
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
	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M2: Memory Observer  [%s]                                                  ║\n", now)
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

func drainOOMEvents(c *collector.MemoryCollector, log *slog.Logger, prom *exporter.PrometheusExporter) {
	events, err := c.ReadOOMEvents()
	if err != nil {
		log.Error("OOM event read error", "err", err)
		return
	}
	for _, ev := range events {
		if prom != nil {
			prom.UpdateOOM(ev.ContainerName)
		}
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

func printIOTable(c *collector.IoCollector, log *slog.Logger, cfg displayConfig, prom *exporter.PrometheusExporter) {
	samples, err := c.Collect()
	if err != nil {
		log.Error("I/O collect error", "err", err)
		return
	}

	if prom != nil {
		prom.UpdateIO(samples)
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

// ─── M6 loader ───────────────────────────────────────────────────────────────

func loadSyscall(objPath string, resolver *cgroup.Resolver, log *slog.Logger) (*collector.SyscallCollector, []link.Link, error) {
	log.Info("loading M6 Syscall BPF object", "path", objPath)
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

	log.Info("M6 Syscall probes attached", "count", len(links))
	return sysColl, links, nil
}

// ─── M4 display ───────────────────────────────────────────────────────────────

func printNetTable(c *collector.NetworkCollector, log *slog.Logger, cfg displayConfig, prom *exporter.PrometheusExporter) {
	summaries, err := c.CollectSummary()
	if err != nil {
		log.Error("Network collect error", "err", err)
		return
	}

	if prom != nil {
		prom.UpdateNetwork(summaries)
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

// ─── M6 display ───────────────────────────────────────────────────────────────

func printSyscallTable(c *collector.SyscallCollector, log *slog.Logger, cfg displayConfig, prom *exporter.PrometheusExporter) {
	all, err := c.Collect()
	if err != nil {
		log.Error("Syscall collect error", "err", err)
		return
	}

	if prom != nil {
		prom.UpdateSyscalls(all)
	}

	// Compute top 5 manually for display
	byContainer := make(map[string][]collector.SyscallSummary)
	for _, s := range all {
		byContainer[s.ContainerName] = append(byContainer[s.ContainerName], s)
	}
	var summaries []collector.SyscallSummary
	for _, entries := range byContainer {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Count > entries[j].Count
		})
		if len(entries) > 5 {
			entries = entries[:5]
		}
		for i := range entries {
			entries[i].Rank = i + 1
		}
		summaries = append(summaries, entries...)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].ContainerName != summaries[j].ContainerName {
			return summaries[i].ContainerName < summaries[j].ContainerName
		}
		return summaries[i].Rank < summaries[j].Rank
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
	fmt.Printf("\n╔════════════════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  M6: Syscall Observer  [%s]                                                          ║\n", now)
	fmt.Printf("╠══════════════════════════╦══════╦══════════════╦════════════╦═══════════╦═════════════════╣\n")
	fmt.Printf("║ Container                ║ Rank ║ Syscall      ║ Count      ║ Failures  ║ Avg Latency (ms)║\n")
	fmt.Printf("╠══════════════════════════╬══════╬══════════════╬════════════╬═══════════╬═════════════════╣\n")
	if len(summaries) == 0 {
		fmt.Printf("║ (no Syscall activity)                                                                        ║\n")
	}
	for _, s := range summaries {
		rankStr := fmt.Sprintf("#%d", s.Rank)
		fmt.Printf("║ %-24s ║ %-4s ║ %-12s ║ %10d ║ %9d ║ %15.3f ║\n",
			truncate(s.ContainerName, 24),
			rankStr,
			truncate(s.SyscallName, 12),
			s.Count,
			s.Failures,
			s.AvgLatencyMs,
		)
	}
	fmt.Printf("╚══════════════════════════╩══════╩══════════════╩════════════╩═══════════╩═════════════════╝\n")
}

func drainSlowSyscallEvents(c *collector.SyscallCollector, log *slog.Logger, cfg displayConfig) {
	events, err := c.ReadSlowEvents()
	if err != nil {
		log.Error("Slow syscall event read error", "err", err)
		return
	}
	for _, ev := range events {
		if cfg.containersOnly && !isContainer(ev.ContainerName) {
			continue
		}
		log.Warn("Slow Syscall Detected",
			"container", ev.ContainerName,
			"pid", ev.PID,
			"comm", ev.Comm,
			"syscall", ev.SyscallName,
			"latency_ms", fmt.Sprintf("%.2f", ev.LatencyMs),
		)
	}
}
