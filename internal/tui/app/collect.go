// Package app — dual-tick collector wiring.
//
// collect.go bridges the eBPF collector layer and the TUI message bus.
// It implements the decoupled dual-tick architecture:
//
//	Render tick (100 ms)  → forces a View() redraw from cached state
//	Data  cmd  (1–2 s)    → runs collectors in a goroutine, emits DataMsg
//
// The render path never blocks on BPF map reads.
package app

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ebpf/internal/tui/msg"
	"ebpf/pkg/collector"
	"ebpf/pkg/event"
	"ebpf/pkg/graph"
	"ebpf/pkg/percentile"
	"ebpf/pkg/timeseries"
)

var (
	// Global telemetry singletons for cross-tick state
	latencyAgg = percentile.NewLatencyAggregator()
	tsBuffer   = timeseries.NewBuffer[msg.DataBatch](300)
)

// CollectorSet bundles all optional eBPF collectors.
// Nil fields are silently skipped (e.g. in demo mode).
type CollectorSet struct {
	CPU     *collector.CpuCollector
	Mem     *collector.MemoryCollector
	IO      *collector.IoCollector
	Net     *collector.NetworkCollector
	Syscall *collector.SyscallCollector

	// Security (Phases 1-5)
	Lineage *collector.LineageCollector
	Exec    *collector.ExecCollector
	DNS     *collector.DnsCollector
	PrivEsc *collector.PrivEscCollector
	Escape  *collector.EscapeCollector

	// Security Event Buffer (drained by collectReal)
	SecWriter *TuiSecurityWriter

	// Graph is the live process graph, populated from fork/exec events.
	// Created once in main and shared here.  Never nil after construction.
	Graph *graph.ProcessGraph
}

// ─── TUI Security Writer ──────────────────────────────────────────────────────

// TuiSecurityWriter buffers security events until the next data tick.
type TuiSecurityWriter struct {
	mu     sync.Mutex
	events []event.EventEnvelope
}

func (w *TuiSecurityWriter) Write(ev event.EventEnvelope) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
}

func (w *TuiSecurityWriter) Drain() []event.EventEnvelope {
	w.mu.Lock()
	defer w.mu.Unlock()
	evs := w.events
	w.events = nil
	return evs
}

// DemoContainers is the set of fake container names used in demo mode.
// Includes both real container prefixes (docker:, cri:) and host-level
// cgroups so the containersOnly filter can be exercised in demo mode.
var DemoContainers = []string{
	"docker:nginx", "docker:postgres", "docker:redis",
	"cri:api-server", "cri:etcd",
	"systemd:init.scope", "cgroup:dockerd", "host:kubelet",
}

// ─── Container detection ─────────────────────────────────────────────────────

// isContainer reports whether name looks like a Docker or containerd container.
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

// ─── Render tick ─────────────────────────────────────────────────────────────

// RenderTickCmd returns a tea.Cmd that fires a RenderTickMsg after d.
func RenderTickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return msg.RenderTickMsg(t)
	})
}

// ─── CollectFilter carries the active display filters ─────────────────────────

// CollectFilter is a small value type so we don't import config inside collect.go.
// It is snapshotted by value before the goroutine runs — goroutine-safe.
type CollectFilter struct {
	ContainersOnly bool
	TopN           int
	ShowFiles      bool
	ShowTCP        bool
	ShowSlowSys    bool
}

// ─── Data collection command ──────────────────────────────────────────────────

// CollectCmd returns a tea.Cmd that runs one collection cycle after d and
// emits a msg.DataMsg.  It is re-issued from App.Update on every DataMsg
// receipt, creating a self-rescheduling loop decoupled from the render tick.
//
// BUG FIX: previously cfg was accepted but never forwarded to collectReal,
// so --containers-only had no effect.  Now CollectFilter is passed by value
// and applied at the batch-build layer (single point of truth).
func CollectCmd(d time.Duration, colls *CollectorSet, demo bool, f CollectFilter) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(d)
		if demo {
			return msg.DataMsg{Batch: genDemoBatch(f)}
		}
		return msg.DataMsg{Batch: collectReal(colls, f)}
	}
}

// ─── Real collection ──────────────────────────────────────────────────────────

func collectReal(colls *CollectorSet, f CollectFilter) msg.DataBatch {
	b := msg.DataBatch{Timestamp: time.Now()}

	if colls.CPU != nil {
		if samples, err := colls.CPU.Collect(); err == nil {
			b.CPU = filterCPU(samples, f)
		}
	}
	if colls.Mem != nil {
		if samples, err := colls.Mem.Collect(); err == nil {
			b.Mem = filterMem(samples, f)
		}
		if oomEvs, err := colls.Mem.ReadOOMEvents(); err == nil {
			for _, o := range oomEvs {
				b.Events = append(b.Events, msg.Event{
					At:        o.Timestamp,
					Kind:      msg.EventKindOOM,
					Container: o.ContainerName,
					Message: fmt.Sprintf("🔴 OOM KILL %s pid=%d comm=%s rss=%dKB",
						o.ContainerName, o.VictimPID, o.Comm, o.Pages*4),
					Envelope: &event.EventEnvelope{
						Timestamp:     o.Timestamp,
						CgroupID:      o.CgroupID,
						ContainerName: o.ContainerName,
						PID:           o.VictimPID,
						Process:       o.Comm,
						EventType:     "oom_kill",
						Metadata: map[string]any{
							"rss_kb":        o.Pages * 4,
							"limit_bytes":   o.MemoryLimitBytes,
							"oom_score_adj": o.OOMScoreAdj,
						},
					},
				})
			}
		}
	}
	if colls.IO != nil {
		if samples, err := colls.IO.Collect(); err == nil {
			b.IO = filterIO(samples, f)
			for _, s := range samples {
				if s.ReadIOs > 0 && s.AvgReadLatencyMs > 0 {
					latencyAgg.RecordValues(fmt.Sprintf("%s:io_read", s.ContainerName), int64(s.AvgReadLatencyMs*1000.0), int64(s.ReadIOs))
				}
				if s.WriteIOs > 0 && s.AvgWriteLatencyMs > 0 {
					latencyAgg.RecordValues(fmt.Sprintf("%s:io_write", s.ContainerName), int64(s.AvgWriteLatencyMs*1000.0), int64(s.WriteIOs))
				}
			}
		}
		if f.ShowFiles {
			if fevs, err := colls.IO.ReadFileEvents(); err == nil {
				for _, fev := range fevs {
					if f.ContainersOnly && !isContainer(fev.ContainerName) {
						continue
					}
					b.Events = append(b.Events, msg.Event{
						At:        fev.Timestamp,
						Kind:      msg.EventKindInfo,
						Container: fev.ContainerName,
						Message: fmt.Sprintf("[FILE] %s  pid=%d  %s  flags=0x%x",
							fev.ContainerName, fev.PID, fev.Filename, fev.Flags),
					})
				}
			}
		}
	}
	if colls.Net != nil {
		if sums, err := colls.Net.CollectSummary(); err == nil {
			b.Net = filterNet(sums, f)
		}
		if f.ShowTCP {
			if tevs, err := colls.Net.ReadTCPEvents(); err == nil {
				for _, t := range tevs {
					if f.ContainersOnly && !isContainer(t.ContainerName) {
						continue
					}
					b.Events = append(b.Events, msg.Event{
						At:        t.Timestamp,
						Kind:      msg.EventKindTCP,
						Container: t.ContainerName,
						Message: fmt.Sprintf("[TCP] %s  %s:%d→%s:%d  %s→%s",
							t.ContainerName, t.Saddr, t.Sport, t.Daddr, t.Dport,
							t.OldState, t.NewState),
					})
				}
			}
		}
	}
	if colls.Syscall != nil {
		if sums, err := colls.Syscall.CollectTop5PerContainer(); err == nil {
			b.Sys = filterSys(sums, f)
			for _, s := range sums {
				if s.Count > 0 && s.AvgLatencyMs > 0 {
					latencyAgg.RecordValues(fmt.Sprintf("%s:sys_%d", s.ContainerName, s.SyscallID), int64(s.AvgLatencyMs*1000.0), int64(s.Count))
				}
			}
		}
		if f.ShowSlowSys {
			if sevs, err := colls.Syscall.ReadSlowEvents(); err == nil {
				for _, s := range sevs {
					if f.ContainersOnly && !isContainer(s.ContainerName) {
						continue
					}
					b.Events = append(b.Events, msg.Event{
						At:        time.Now(),
						Kind:      msg.EventKindSlowSys,
						Container: s.ContainerName,
						Message: fmt.Sprintf("⚠️ SLOW SYSCALL %s pid=%d comm=%s sys_id=%d lat=%.2fms",
							s.ContainerName, s.PID, s.Comm, s.SyscallID, s.LatencyMs),
					})
				}
			}
		}
	}

	// Drain security events (Lineage, Exec, DNS, PrivEsc, Escape)
	// and feed them into the ProcessGraph.
	if colls.Lineage != nil {
		if forkEvs, err := colls.Lineage.ReadForkEvents(); err == nil && colls.Graph != nil {
			for _, ev := range forkEvs {
				// Respect --containers-only: skip non-container cgroups.
				if f.ContainersOnly && !isContainer(ev.ContainerName) {
					continue
				}
				colls.Graph.AddFork(ev)
			}
		}
	}
	if colls.Exec != nil {
		if execEvs, err := colls.Exec.ReadExecEvents(); err == nil && colls.Graph != nil {
			for _, ev := range execEvs {
				// Respect --containers-only: skip non-container cgroups.
				if f.ContainersOnly && !isContainer(ev.ContainerName) {
					continue
				}
				colls.Graph.AddExec(ev)
			}
		}
	}
	if colls.DNS != nil {
		if dnsEvs, err := colls.DNS.ReadDNSEvents(); err == nil {
			for _, ev := range dnsEvs {
				if lat, ok := ev.Metadata["latency_ms"].(float64); ok {
					latencyAgg.Record(fmt.Sprintf("%s:dns", ev.ContainerName), int64(lat*1000.0))
				}
			}
		}
	}
	if colls.PrivEsc != nil {
		_, _ = colls.PrivEsc.ReadPrivEscEvents()
	}
	if colls.Escape != nil {
		_, _ = colls.Escape.ReadEscapeEvents()
	}

	if colls.SecWriter != nil {
		secEvents := colls.SecWriter.Drain()
		grouped := make(map[string]*msg.Event)
		var order []string

		for _, ev := range secEvents {
			if f.ContainersOnly && !isContainer(ev.ContainerName) {
				continue
			}
			// Skip extremely noisy container setup events from container runtime (runc)
			if strings.HasPrefix(strings.ToLower(ev.Process), "runc") {
				continue
			}

			key := fmt.Sprintf("%s:%s:%s", ev.ContainerName, ev.EventType, ev.Process)
			if existing, ok := grouped[key]; ok {
				existing.Count++
				existing.At = ev.Timestamp // Update to latest timestamp
			} else {
				envelope := ev
				grouped[key] = &msg.Event{
					At:        ev.Timestamp,
					Kind:      msg.EventKindSecurity,
					Container: ev.ContainerName,
					Message:   fmt.Sprintf("[%s] %s", ev.EventType, ev.Process),
					Envelope:  &envelope,
					Count:     1,
				}
				order = append(order, key)

				// Correlate security event to the process graph node.
				if colls.Graph != nil {
					colls.Graph.CorrelateEvent(ev.CgroupID, ev.PID, &envelope)
				}
			}
		}

		for _, key := range order {
			b.Events = append(b.Events, *grouped[key])
		}
	}

	// Attach a lock-free graph snapshot to the batch.
	if colls.Graph != nil {
		b.Graph = colls.Graph.Snapshot()
	}

	// Rotate and snapshot percentiles
	latencyAgg.Tick()
	b.Percentiles = latencyAgg.Snapshot()

	// Push to time-series history
	tsBuffer.Push(b)

	return b
}

// ─── Per-type filters ─────────────────────────────────────────────────────────

func filterCPU(in []collector.CpuSample, f CollectFilter) []collector.CpuSample {
	out := make([]collector.CpuSample, 0, len(in))
	for _, s := range in {
		if f.ContainersOnly && !isContainer(s.ContainerName) {
			continue
		}
		out = append(out, s)
	}
	if f.TopN > 0 && len(out) > f.TopN {
		return out[:f.TopN]
	}
	return out
}

func filterMem(in []collector.MemSample, f CollectFilter) []collector.MemSample {
	out := make([]collector.MemSample, 0, len(in))
	for _, s := range in {
		if f.ContainersOnly && !isContainer(s.ContainerName) {
			continue
		}
		out = append(out, s)
	}
	if f.TopN > 0 && len(out) > f.TopN {
		return out[:f.TopN]
	}
	return out
}

func filterIO(in []collector.IoSample, f CollectFilter) []collector.IoSample {
	out := make([]collector.IoSample, 0, len(in))
	for _, s := range in {
		if f.ContainersOnly && !isContainer(s.ContainerName) {
			continue
		}
		out = append(out, s)
	}
	if f.TopN > 0 && len(out) > f.TopN {
		return out[:f.TopN]
	}
	return out
}

func filterNet(in []collector.NetSummary, f CollectFilter) []collector.NetSummary {
	out := make([]collector.NetSummary, 0, len(in))
	for _, s := range in {
		if f.ContainersOnly && !isContainer(s.ContainerName) {
			continue
		}
		out = append(out, s)
	}
	if f.TopN > 0 && len(out) > f.TopN {
		return out[:f.TopN]
	}
	return out
}

func filterSys(in []collector.SyscallSummary, f CollectFilter) []collector.SyscallSummary {
	out := make([]collector.SyscallSummary, 0, len(in))
	for _, s := range in {
		if f.ContainersOnly && !isContainer(s.ContainerName) {
			continue
		}
		out = append(out, s)
	}
	if f.TopN > 0 && len(out) > f.TopN {
		return out[:f.TopN]
	}
	return out
}

// ─── Demo generation ──────────────────────────────────────────────────────────

// genDemoBatch produces a random DataBatch for demo mode.
// Respects ContainersOnly: host-level cgroups (systemd:, cgroup:, host:)
// are excluded when set, matching production behavior.
func genDemoBatch(f CollectFilter) msg.DataBatch {
	b := msg.DataBatch{Timestamp: time.Now()}
	seed := time.Now().UnixNano()
	rnd := func(max float64) float64 {
		seed = seed*6364136223846793005 + 1442695040888963407
		v := float64((seed>>33)&0x7fffffff) / 0x7fffffff
		return v * max
	}
	rndi := func(max int) int { return int(rnd(float64(max))) }

	for _, c := range DemoContainers {
		if f.ContainersOnly && !isContainer(c) {
			continue // skip systemd:, cgroup:, host: entries
		}
		b.CPU = append(b.CPU, collector.CpuSample{
			ContainerName:      c,
			CPUSeconds:         rnd(2),
			RunqLatencySeconds: rnd(0.005),
			CtxSwitchesPerSec:  rnd(1000),
			ThreadCount:        uint32(rndi(50) + 1),
		})
		b.Mem = append(b.Mem, collector.MemSample{
			ContainerName:    c,
			MemoryBytes:      uint64(rnd(512 * 1024 * 1024)),
			MemoryLimitBytes: 1024 * 1024 * 1024,
			FaultsPerSec:     rnd(200),
		})
		b.IO = append(b.IO, collector.IoSample{
			ContainerName:     c,
			ReadBytesPerSec:   rnd(5 * 1024 * 1024),
			WriteBytesPerSec:  rnd(2 * 1024 * 1024),
			AvgReadLatencyMs:  rnd(3),
			AvgWriteLatencyMs: rnd(3),
		})
		b.Net = append(b.Net, collector.NetSummary{
			ContainerName:    c,
			ActiveFlows:      rndi(20),
			Established:      rndi(15),
			TimeWait:         rndi(5),
			CloseWait:        rndi(3),
			TotalRetransmits: uint32(rndi(10)),
		})
		tcpStates := []string{"ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE_WAIT"}
		s1 := tcpStates[rndi(len(tcpStates))]
		s2 := tcpStates[rndi(len(tcpStates))]
		b.Events = append(b.Events, msg.Event{
			At:        time.Now(),
			Kind:      msg.EventKindTCP,
			Container: c,
			Message:   fmt.Sprintf("[TCP] %s  %s → %s", c, s1, s2),
		})
		if rndi(10) == 0 {
			b.Events = append(b.Events, msg.Event{
				At:        time.Now(),
				Kind:      msg.EventKindOOM,
				Container: c,
				Message:   fmt.Sprintf("🔴 OOM KILL %s pid=%d comm=%s rss=%dKB", c, rndi(10000)+1000, "stress", rndi(128*1024)),
				Envelope: &event.EventEnvelope{
					Timestamp:     time.Now(),
					CgroupID:      uint64(rndi(100)),
					ContainerName: c,
					PID:           uint32(rndi(10000) + 1000),
					Process:       "stress",
					EventType:     "oom_kill",
					Metadata: map[string]any{
						"rss_kb":        uint64(rndi(256 * 1024)),
						"limit_bytes":   uint64(512 * 1024 * 1024),
						"oom_score_adj": int32(500),
					},
				},
			})
		}
	}

	// Attach a stable demo process graph (rebuilt once per batch).
	b.Graph = buildDemoGraph(f)
	return b
}

// buildDemoGraph constructs a synthetic process tree resembling a real
// containerised workload.  Called only in demo mode.
// Each demo cgroup maps to a named docker: container so the TUI can display
// readable names and respect --containers-only filtering.
func buildDemoGraph(f CollectFilter) *graph.Snapshot {
	g := graph.New(512)
	now := time.Now()

	// cgroup → docker container name mapping (mirrors DemoContainers).
	cgName := map[uint64]string{
		1: "docker:nginx",
		2: "docker:postgres",
		3: "docker:redis",
	}

	mkFork := func(cgroupID uint64, pid, ppid uint32, comm, parent string, secsAgo float64, sid uint32) event.EventEnvelope {
		cn := cgName[cgroupID]
		env := event.EventEnvelope{
			Timestamp:     now.Add(-time.Duration(secsAgo * float64(time.Second))),
			CgroupID:      cgroupID,
			ContainerName: cn,
			PID:           pid,
			PPID:          ppid,
			Process:       comm,
			ParentProcess: parent,
			EventType:     event.EventTypeFork,
		}
		if sid != 0 {
			env.Metadata = map[string]any{"sid": sid}
		}
		return env
	}
	mkExec := func(cgroupID uint64, pid, ppid uint32, comm, path string) event.EventEnvelope {
		cn := cgName[cgroupID]
		return event.EventEnvelope{
			Timestamp:     now.Add(-time.Second),
			CgroupID:      cgroupID,
			ContainerName: cn,
			PID:           pid,
			PPID:          ppid,
			Process:       comm,
			EventType:     event.EventTypeExec,
			Metadata:      map[string]any{"full_path": path},
		}
	}

	// Helper: add fork only when not filtered.
	addFork := func(env event.EventEnvelope) {
		if f.ContainersOnly && !isContainer(env.ContainerName) {
			return
		}
		g.AddFork(env)
	}
	addExec := func(env event.EventEnvelope) {
		if f.ContainersOnly && !isContainer(env.ContainerName) {
			return
		}
		g.AddExec(env)
	}

	// ── cgroup 1: docker:nginx ────────────────────────────────────────────────
	addFork(mkFork(1, 1, 0, "containerd", "", 120, 1))
	addFork(mkFork(1, 100, 1, "dockerd", "containerd", 110, 1))
	addFork(mkFork(1, 200, 100, "runc", "dockerd", 100, 2))
	addFork(mkFork(1, 301, 200, "nginx", "runc", 95, 2))
	addFork(mkFork(1, 302, 200, "nginx", "runc", 94, 2))
	addFork(mkFork(1, 303, 200, "nginx", "runc", 93, 2))
	addExec(mkExec(1, 301, 200, "nginx", "/usr/sbin/nginx"))
	addExec(mkExec(1, 302, 200, "nginx", "/usr/sbin/nginx"))
	addExec(mkExec(1, 303, 200, "nginx", "/usr/sbin/nginx"))

	// ── cgroup 2: docker:postgres ─────────────────────────────────────────────
	addFork(mkFork(2, 1, 0, "containerd", "", 80, 3))
	addFork(mkFork(2, 400, 1, "runc", "containerd", 79, 3))
	addFork(mkFork(2, 500, 400, "python3", "runc", 70, 3))
	addFork(mkFork(2, 501, 500, "gunicorn", "python3", 65, 3))
	addFork(mkFork(2, 601, 501, "worker", "gunicorn", 60, 3))
	addFork(mkFork(2, 602, 501, "worker", "gunicorn", 59, 3))
	addFork(mkFork(2, 603, 501, "worker", "gunicorn", 58, 3))
	addExec(mkExec(2, 500, 400, "python3", "/usr/bin/python3"))
	addExec(mkExec(2, 501, 500, "gunicorn", "/usr/local/bin/gunicorn"))

	// ── cgroup 3: docker:redis ────────────────────────────────────────────────
	addFork(mkFork(3, 1, 0, "postgres", "", 50, 4))
	addFork(mkFork(3, 700, 1, "postgres", "postgres", 49, 4))
	addFork(mkFork(3, 701, 1, "postgres", "postgres", 48, 4))
	addFork(mkFork(3, 702, 1, "postgres", "postgres", 47, 4))
	addExec(mkExec(3, 1, 0, "postgres", "/usr/lib/postgresql/14/bin/postgres"))

	// Simulate a privilege escalation event on the gunicorn worker.
	privEv := &event.EventEnvelope{
		Timestamp: now.Add(-5 * time.Second),
		CgroupID:  2,
		PID:       601,
		EventType: event.EventTypePrivEsc,
		Process:   "worker",
		Metadata:  map[string]any{"cap": "CAP_SYS_ADMIN"},
	}
	g.CorrelateEvent(2, 601, privEv)

	// Simulate a DNS query from nginx.
	dnsEv := &event.EventEnvelope{
		Timestamp: now.Add(-2 * time.Second),
		CgroupID:  1,
		PID:       301,
		EventType: event.EventTypeDNSQuery,
		Process:   "nginx",
		Metadata:  map[string]any{"query": "api.internal."},
	}
	g.CorrelateEvent(1, 301, dnsEv)

	return g.Snapshot()
}
