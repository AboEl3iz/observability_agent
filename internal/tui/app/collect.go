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
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ebpf/internal/tui/msg"
	"ebpf/pkg/collector"
)

// CollectorSet bundles all optional eBPF collectors.
// Nil fields are silently skipped (e.g. in demo mode).
type CollectorSet struct {
	CPU     *collector.CpuCollector
	Mem     *collector.MemoryCollector
	IO      *collector.IoCollector
	Net     *collector.NetworkCollector
	Syscall *collector.SyscallCollector
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
	return strings.HasPrefix(name, "docker:") || strings.HasPrefix(name, "cri:")
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
				if f.ContainersOnly && !isContainer(o.ContainerName) {
					continue
				}
				b.Events = append(b.Events, msg.Event{
					At:        o.Timestamp,
					Kind:      msg.EventKindOOM,
					Container: o.ContainerName,
					Message: fmt.Sprintf("🔴 OOM KILL %s pid=%d comm=%s rss=%dKB",
						o.ContainerName, o.VictimPID, o.Comm, o.Pages*4),
				})
			}
		}
	}
	if colls.IO != nil {
		if samples, err := colls.IO.Collect(); err == nil {
			b.IO = filterIO(samples, f)
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
	}
	return b
}
