package main

import (
	"flag"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf/link"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/collector"
)

// ─── displayConfig ────────────────────────────────────────────────────────────

type displayConfig struct {
	containersOnly bool
	topN           int
	showFiles      bool
	showTCP        bool
	showSlowSys    bool
}

// ─── Palette ──────────────────────────────────────────────────────────────────

var accentPalette = []lipgloss.Color{
	"#7C3AED", "#0EA5E9", "#10B981", "#F59E0B",
	"#EF4444", "#EC4899", "#14B8A6", "#8B5CF6",
}

func accentFor(ts string) lipgloss.Color {
	h := 0
	for _, c := range ts {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return accentPalette[h%len(accentPalette)]
}

// ─── Row types ────────────────────────────────────────────────────────────────

type CpuRow struct{ Container string; CPUSec, RunqMs, CtxPerSec float64; Threads int }
type MemRow struct{ Container, LimitMb string; RSSMb, FaultsSec float64 }
type IoRow  struct{ Container string; ReadKBs, WriteKBs, RLatMs, WLatMs float64 }
type NetRow struct{ Container string; Flows, Established, TimeWait, CloseWait, Retransmits int }
type SysRow struct{ Container string; SyscallID uint32; SyscallName string; Count, Failures int; AvgLatMs float64 }

type Batch struct {
	Timestamp string
	Accent    lipgloss.Color
	CPU       []CpuRow
	Mem       []MemRow
	IO        []IoRow
	Net       []NetRow
	Sys       []SysRow
}

type EventKind int

const (
	EvInfo EventKind = iota
	EvTCP
	EvError
	EvOOM
	EvSlowSys
)

type Event struct {
	At      time.Time
	Kind    EventKind
	Message string
}

// ─── Bubbletea messages ───────────────────────────────────────────────────────

type tickMsg time.Time

// ─── Model ────────────────────────────────────────────────────────────────────

type model struct {
	width, height int
	batches       []Batch
	events        []Event

	// line-level viewport offsets (math.MaxInt = follow/live mode)
	metricsOffset int
	eventsOffset  int
	metricsFollow bool // auto-scroll to bottom
	eventsFollow  bool
	focusedPane   int  // 0=metrics 1=events

	// real collectors (nil = demo mode)
	cpuColl *collector.CpuCollector
	memColl *collector.MemoryCollector
	ioColl  *collector.IoCollector
	netColl *collector.NetworkCollector
	sysColl *collector.SyscallCollector

	cfg      displayConfig
	demo     bool
	interval time.Duration

	// demo helpers
	demoContainers []string
}

func newModel(
	demo bool,
	interval time.Duration,
	cfg displayConfig,
	cpu *collector.CpuCollector,
	mem *collector.MemoryCollector,
	io *collector.IoCollector,
	net *collector.NetworkCollector,
	sys *collector.SyscallCollector,
) model {
	return model{
		demo:          demo,
		interval:      interval,
		cfg:           cfg,
		cpuColl:       cpu,
		memColl:       mem,
		ioColl:        io,
		netColl:       net,
		sysColl:       sys,
		metricsFollow: true,
		eventsFollow:  true,
		metricsOffset: math.MaxInt32,
		eventsOffset:  math.MaxInt32,
		demoContainers: []string{
			"docker:nginx", "docker:postgres", "docker:redis",
			"cri:api-server", "cri:etcd",
			"systemd:init.scope", "cgroup:dockerd", "host:kubelet",
		},
	}
}

func (m model) Init() tea.Cmd {
	return tea.Tick(m.interval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ─── Update ───────────────────────────────────────────────────────────────────

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tickMsg:
		if m.demo {
			m.batches = append(m.batches, m.genDemoBatch())
			m.events = append(m.events, m.genDemoEvents()...)
		} else {
			b, evs := m.collectReal()
			m.batches = append(m.batches, b)
			m.events = append(m.events, evs...)
		}
		if len(m.batches) > 100 { m.batches = m.batches[len(m.batches)-100:] }
		if len(m.events) > 500  { m.events  = m.events[len(m.events)-500:]   }
		// follow mode: keep viewport pinned to bottom
		if m.metricsFollow { m.metricsOffset = math.MaxInt32 }
		if m.eventsFollow  { m.eventsOffset  = math.MaxInt32 }
		return m, tea.Tick(m.interval, func(t time.Time) tea.Msg { return tickMsg(t) })

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.focusedPane = 1 - m.focusedPane
		case "up", "k":
			if m.focusedPane == 0 {
				m.metricsFollow = false
				if m.metricsOffset > 0 { m.metricsOffset-- }
			} else {
				m.eventsFollow = false
				if m.eventsOffset > 0 { m.eventsOffset-- }
			}
		case "down", "j":
			if m.focusedPane == 0 {
				m.metricsOffset++ // clamped in View
			} else {
				m.eventsOffset++
			}
		case "pgup":
			if m.focusedPane == 0 {
				m.metricsFollow = false
				if m.metricsOffset > 10 { m.metricsOffset -= 10 } else { m.metricsOffset = 0 }
			} else {
				m.eventsFollow = false
				if m.eventsOffset > 10 { m.eventsOffset -= 10 } else { m.eventsOffset = 0 }
			}
		case "pgdown":
			if m.focusedPane == 0 { m.metricsOffset += 10 } else { m.eventsOffset += 10 }
		case "g":
			if m.focusedPane == 0 {
				m.metricsFollow = false; m.metricsOffset = 0
			} else {
				m.eventsFollow = false; m.eventsOffset = 0
			}
		case "G":
			if m.focusedPane == 0 {
				m.metricsFollow = true; m.metricsOffset = math.MaxInt32
			} else {
				m.eventsFollow = true; m.eventsOffset = math.MaxInt32
			}
		}
	}
	return m, nil
}

// ─── Real collector integration ───────────────────────────────────────────────

func (m *model) collectReal() (Batch, []Event) {
	ts := time.Now().Format("15:04:05")
	b := Batch{Timestamp: ts, Accent: accentFor(ts)}
	var evs []Event

	if m.cpuColl != nil {
		if samples, err := m.cpuColl.Collect(); err == nil {
			sort.Slice(samples, func(i, j int) bool {
				return samples[i].CPUSeconds > samples[j].CPUSeconds
			})
			b.CPU = cpuRows(samples, m.cfg)
		}
	}
	if m.memColl != nil {
		if samples, err := m.memColl.Collect(); err == nil {
			sort.Slice(samples, func(i, j int) bool {
				return samples[i].MemoryBytes > samples[j].MemoryBytes
			})
			b.Mem = memRows(samples, m.cfg)
		}
		if oomEvs, err := m.memColl.ReadOOMEvents(); err == nil {
			for _, o := range oomEvs {
				evs = append(evs, Event{
					At:   o.Timestamp,
					Kind: EvOOM,
					Message: fmt.Sprintf("🔴 OOM KILL %s pid=%d comm=%s rss=%dKB",
						o.ContainerName, o.VictimPID, o.Comm, o.Pages*4),
				})
			}
		}
	}
	if m.ioColl != nil {
		if samples, err := m.ioColl.Collect(); err == nil {
			sort.Slice(samples, func(i, j int) bool {
				return (samples[i].ReadBytesPerSec + samples[i].WriteBytesPerSec) >
					(samples[j].ReadBytesPerSec + samples[j].WriteBytesPerSec)
			})
			b.IO = ioRows(samples, m.cfg)
		}
		if m.cfg.showFiles {
			if fevs, err := m.ioColl.ReadFileEvents(); err == nil {
				for _, f := range fevs {
					if m.cfg.containersOnly && !isContainer(f.ContainerName) {
						continue
					}
					evs = append(evs, Event{
						At:   f.Timestamp,
						Kind: EvInfo,
						Message: fmt.Sprintf("[FILE] %s  pid=%d  %s  flags=0x%x",
							f.ContainerName, f.PID, f.Filename, f.Flags),
					})
				}
			}
		}
	}
	if m.netColl != nil {
		if summaries, err := m.netColl.CollectSummary(); err == nil {
			sort.Slice(summaries, func(i, j int) bool {
				return summaries[i].ActiveFlows > summaries[j].ActiveFlows
			})
			b.Net = netRows(summaries, m.cfg)
		}
		if m.cfg.showTCP {
			if tevs, err := m.netColl.ReadTCPEvents(); err == nil {
				for _, t := range tevs {
					if m.cfg.containersOnly && !isContainer(t.ContainerName) {
						continue
					}
					evs = append(evs, Event{
						At:   t.Timestamp,
						Kind: EvTCP,
						Message: fmt.Sprintf("[TCP] %s  %s:%d→%s:%d  %s→%s",
							t.ContainerName, t.Saddr, t.Sport, t.Daddr, t.Dport,
							t.OldState, t.NewState),
					})
				}
			}
		}
	}
	if m.sysColl != nil {
		if summaries, err := m.sysColl.Collect(); err == nil {
			sort.Slice(summaries, func(i, j int) bool {
				return summaries[i].Count > summaries[j].Count
			})
			b.Sys = sysRows(summaries, m.cfg)
		}
		if m.cfg.showSlowSys {
			if sevs, err := m.sysColl.ReadSlowEvents(); err == nil {
				for _, s := range sevs {
					if m.cfg.containersOnly && !isContainer(s.ContainerName) {
						continue
					}
					evs = append(evs, Event{
						At:   time.Now(),
						Kind: EvSlowSys,
						Message: fmt.Sprintf("⚠️ SLOW SYSCALL %s pid=%d comm=%s sys_id=%d lat=%.2fms",
							s.ContainerName, s.PID, s.Comm, s.SyscallID, s.LatencyMs),
					})
				}
			}
		}
	}
	return b, evs
}

// ─── Demo generators ──────────────────────────────────────────────────────────

func (m *model) genDemoBatch() Batch {
	ts := time.Now().Format("15:04:05")
	b := Batch{Timestamp: ts, Accent: accentFor(ts)}
	for _, c := range m.demoContainers {
		// Honour --containers-only: skip host-process cgroups when flag is set.
		if m.cfg.containersOnly && !isContainer(c) {
			continue
		}
		b.CPU = append(b.CPU, CpuRow{c, rand.Float64() * 2, rand.Float64() * 5, rand.Float64() * 1000, rand.Intn(50) + 1})
		b.Mem = append(b.Mem, MemRow{c, "1024.0", rand.Float64() * 512, rand.Float64() * 200})
		b.IO  = append(b.IO,  IoRow{c, rand.Float64() * 5000, rand.Float64() * 2000, rand.Float64() * 3, rand.Float64() * 3})
		b.Net = append(b.Net, NetRow{c, rand.Intn(20), rand.Intn(15), rand.Intn(5), rand.Intn(3), rand.Intn(10)})
		b.Sys = append(b.Sys, SysRow{c, uint32(rand.Intn(300)), "sys_demo", rand.Intn(10000), rand.Intn(50), rand.Float64() * 5})
	}
	return b
}

var demoTCPStates = []string{"ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE_WAIT", "LISTEN", "FIN_WAIT1"}

func (m *model) genDemoEvents() []Event {
	var evs []Event
	c := m.demoContainers[rand.Intn(len(m.demoContainers))]
	for i := 0; i < rand.Intn(4)+1; i++ {
		r := rand.Intn(10)
		switch {
		case r < 4:
			s1 := demoTCPStates[rand.Intn(len(demoTCPStates))]
			s2 := demoTCPStates[rand.Intn(len(demoTCPStates))]
			evs = append(evs, Event{time.Now(), EvTCP, fmt.Sprintf("[TCP] %s  %s → %s", c, s1, s2)})
		case r < 7:
			evs = append(evs, Event{time.Now(), EvInfo, fmt.Sprintf("[INFO] %s probe ok, ctx-sw=%d", c, rand.Intn(500))})
		case r < 9:
			evs = append(evs, Event{time.Now(), EvError, fmt.Sprintf("[ERR] %s retransmit spike: %d pkts", c, rand.Intn(50)+10)})
		case r < 10:
			evs = append(evs, Event{time.Now(), EvSlowSys, fmt.Sprintf("⚠️ SLOW SYSCALL %s pid=%d sys_id=%d lat=%.2fms", c, rand.Intn(5000), rand.Intn(300), rand.Float64()*100+50)})
		default:
			evs = append(evs, Event{time.Now(), EvOOM, fmt.Sprintf("🔴 OOM KILL %s pid=%d rss=%dMB", c, rand.Intn(9999)+1000, rand.Intn(512)+128)})
		}
	}
	return evs
}

// ─── Styles ───────────────────────────────────────────────────────────────────

var (
	styleHeader = lipgloss.NewStyle().Background(lipgloss.Color("#161B22")).Foreground(lipgloss.Color("#E6EDF3")).Bold(true).Padding(0, 2)
	styleFooter = lipgloss.NewStyle().Background(lipgloss.Color("#161B22")).Foreground(lipgloss.Color("#8B949E")).Padding(0, 2)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("#484F58"))
	styleCol    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E")).Italic(true)
	styleEvInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("#58A6FF"))
	styleEvTCP   = lipgloss.NewStyle().Foreground(lipgloss.Color("#3FB950"))
	styleEvError = lipgloss.NewStyle().Foreground(lipgloss.Color("#F85149"))
	styleEvOOM   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF7B72")).Bold(true)
	styleEvSlowSys = lipgloss.NewStyle().Foreground(lipgloss.Color("#EAB308"))
)

func trunc(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n-1] + "…"
}

// ─── View ─────────────────────────────────────────────────────────────────────

func (m model) View() string {
	if m.width == 0 { return "Initialising…" }
	hdr := m.viewHeader()
	ftr := m.viewFooter()
	usable := m.height - lipgloss.Height(hdr) - lipgloss.Height(ftr)
	if usable < 6 { usable = 6 }

	// horizontal separator
	sepLine := lipgloss.NewStyle().Foreground(lipgloss.Color("#30363D")).Render(strings.Repeat("─", m.width))
	paneSpace := usable - 1 // 1 for separator
	topH := int(float64(paneSpace) * 0.60)
	botH := paneSpace - topH
	if topH < 3 { topH = 3 }
	if botH < 3 { botH = 3 }

	top := m.viewMetrics(topH)
	bot := m.viewEvents(botH)
	return lipgloss.JoinVertical(lipgloss.Left, hdr, top, sepLine, bot, ftr)
}

// ─── Metrics pane (top, line-level viewport) ──────────────────────────────────

func (m model) viewMetrics(h int) string {
	focused := m.focusedPane == 0
	tc := lipgloss.Color("#58A6FF")
	if focused { tc = lipgloss.Color("#79C0FF") }
	ind := ""
	if m.metricsFollow { ind = " ● LIVE" } else { ind = " ‖ PAUSED" }
	title := lipgloss.NewStyle().Width(m.width).Background(lipgloss.Color("#161B22")).
		Foreground(tc).Bold(true).Padding(0, 1).
		Render(fmt.Sprintf("  ⬡  Aggregated Metrics  [%d batches]%s", len(m.batches), ind))

	bodyH := h - 1
	all := m.allMetricsLines()
	maxOff := len(all) - bodyH
	if maxOff < 0 { maxOff = 0 }
	off := m.metricsOffset
	if off > maxOff { off = maxOff }

	end := off + bodyH
	if end > len(all) { end = len(all) }
	visible := all[off:end]
	for len(visible) < bodyH { visible = append(visible, "") }
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(visible, "\n"))
}

func (m model) allMetricsLines() []string {
	if len(m.batches) == 0 {
		return []string{styleDim.Render("  Waiting for first observation batch…")}
	}
	var lines []string
	for _, b := range m.batches {
		lines = append(lines, m.renderCardLines(b)...)
	}
	return lines
}

func (m model) renderCardLines(b Batch) []string {
	ac := b.Accent
	innerW := m.width - 4
	if innerW < 20 { innerW = 20 }
	borderSt := lipgloss.NewStyle().
		BorderStyle(lipgloss.DoubleBorder()).BorderForeground(ac).
		Width(innerW).Padding(0, 1)
	heading := lipgloss.NewStyle().Foreground(ac).Bold(true).
		Render(fmt.Sprintf("  ● Batch  %s", b.Timestamp))
	parts := []string{
		heading,
		renderCPUTable(b.CPU, ac, innerW-2),
		renderMemTable(b.Mem, ac, innerW-2),
		renderIOTable(b.IO, ac, innerW-2),
		renderNetTable(b.Net, ac, innerW-2),
		renderSysTable(b.Sys, ac, innerW-2),
	}
	card := borderSt.Render(strings.Join(parts, "\n"))
	return append(strings.Split(card, "\n"), "")
}

// ─── Events pane (bottom, full-width with text wrapping) ─────────────────────

func (m model) viewEvents(h int) string {
	focused := m.focusedPane == 1
	tc := lipgloss.Color("#F59E0B")
	if focused { tc = lipgloss.Color("#FCA522") }
	ind := ""
	if m.eventsFollow { ind = " ● LIVE" } else { ind = " ‖ PAUSED" }
	title := lipgloss.NewStyle().Width(m.width).Background(lipgloss.Color("#161B22")).
		Foreground(tc).Bold(true).Padding(0, 1).
		Render(fmt.Sprintf("  ⚡ Real-time Events  [%d events]%s", len(m.events), ind))

	bodyH := h - 1
	all := m.allEventLines()
	maxOff := len(all) - bodyH
	if maxOff < 0 { maxOff = 0 }
	off := m.eventsOffset
	if off > maxOff { off = maxOff }

	end := off + bodyH
	if end > len(all) { end = len(all) }
	visible := all[off:end]
	for len(visible) < bodyH { visible = append(visible, "") }
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(visible, "\n"))
}

func (m model) allEventLines() []string {
	if len(m.events) == 0 {
		return []string{styleDim.Render("  No events yet…")}
	}
	const tsW = 9 // "15:04:05"
	availFirst := m.width - tsW - 2
	if availFirst < 20 { availFirst = 20 }
	var lines []string
	for _, ev := range m.events {
		ts := styleDim.Render(ev.At.Format("15:04:05"))
		msg := ev.Message
		// word-wrap the raw message to terminal width
		var chunks []string
		avail := availFirst
		for len(msg) > avail {
			chunks = append(chunks, msg[:avail])
			msg = msg[avail:]
			avail = m.width - tsW - 4 // indent continuation
		}
		if len(msg) > 0 { chunks = append(chunks, msg) }
		if len(chunks) == 0 { chunks = []string{""} }
		indent := strings.Repeat(" ", tsW+2)
		for i, ch := range chunks {
			var styled string
			switch ev.Kind {
			case EvInfo:  styled = styleEvInfo.Render(ch)
			case EvTCP:   styled = styleEvTCP.Render(ch)
			case EvError: styled = styleEvError.Render(ch)
			case EvOOM:   styled = styleEvOOM.Render(ch)
			case EvSlowSys: styled = styleEvSlowSys.Render(ch)
			}
			if i == 0 {
				lines = append(lines, ts+" "+styled)
			} else {
				lines = append(lines, indent+styled)
			}
		}
	}
	return lines
}

func (m model) viewHeader() string {
	now  := time.Now().Format("2006-01-02  15:04:05")
	mode := "LIVE"
	if m.demo { mode = "DEMO" }
	mBg := lipgloss.Color("#3FB950")
	if m.demo { mBg = lipgloss.Color("#F59E0B") }
	badge := lipgloss.NewStyle().Background(mBg).Foreground(lipgloss.Color("#0D1117")).Bold(true).Padding(0, 1).Render(mode)
	ts    := styleHeader.Copy().Foreground(lipgloss.Color("#8B949E")).Render("  " + now)
	left  := "  ◉ eBPF Container Observer"
	gap   := m.width - len(left) - lipgloss.Width(badge) - lipgloss.Width(ts) - 4
	if gap < 0 { gap = 0 }
	return styleHeader.Copy().Width(m.width).Render(left + strings.Repeat(" ", gap) + badge + ts)
}

func (m model) viewFooter() string {
	pane := "[METRICS]"
	if m.focusedPane == 1 { pane = "[EVENTS]" }
	keys := "  Tab switch pane  ↑/↓ j/k scroll  PgUp/Dn  g top  G live  q quit  focus:" + pane
	stats := fmt.Sprintf(" batches:%d events:%d  ", len(m.batches), len(m.events))
	gap := m.width - len(keys) - len(stats)
	if gap < 0 { gap = 0 }
	return styleFooter.Copy().Width(m.width).Render(keys + strings.Repeat(" ", gap) + stats)
}

// ─── Table rendering helpers ──────────────────────────────────────────────────

func sectionLabel(label string, ac lipgloss.Color) string {
	return lipgloss.NewStyle().Foreground(ac).Bold(true).Render(label)
}

func sep(w int) string { return styleDim.Render(strings.Repeat("─", w)) }

func renderCPUTable(rows []CpuRow, ac lipgloss.Color, w int) string {
	var sb strings.Builder
	sb.WriteString(sectionLabel("▸ M1 CPU", ac) + "\n")
	sb.WriteString(styleCol.Render(fmt.Sprintf("  %-22s  %10s  %13s  %9s  %6s", "Container", "CPU(s/Δt)", "RunQ lat(ms)", "ctx-sw/s", "thrds")) + "\n")
	sb.WriteString(sep(w) + "\n")
	if len(rows) == 0 { sb.WriteString(styleDim.Render("  (no data)") + "\n"); return sb.String() }
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-22s  %10.4f  %13.3f  %9.1f  %6d\n", trunc(r.Container, 22), r.CPUSec, r.RunqMs, r.CtxPerSec, r.Threads))
	}
	return sb.String()
}

func renderMemTable(rows []MemRow, ac lipgloss.Color, w int) string {
	var sb strings.Builder
	sb.WriteString(sectionLabel("▸ M2 Memory", ac) + "\n")
	sb.WriteString(styleCol.Render(fmt.Sprintf("  %-22s  %11s  %11s  %14s", "Container", "RSS(MB)", "Limit(MB)", "Faults/s")) + "\n")
	sb.WriteString(sep(w) + "\n")
	if len(rows) == 0 { sb.WriteString(styleDim.Render("  (no data)") + "\n"); return sb.String() }
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-22s  %11.2f  %11s  %14.1f\n", trunc(r.Container, 22), r.RSSMb, r.LimitMb, r.FaultsSec))
	}
	return sb.String()
}

func renderIOTable(rows []IoRow, ac lipgloss.Color, w int) string {
	var sb strings.Builder
	sb.WriteString(sectionLabel("▸ M3 I/O", ac) + "\n")
	sb.WriteString(styleCol.Render(fmt.Sprintf("  %-22s  %12s  %12s  %9s  %9s", "Container", "Read KB/s", "Write KB/s", "R lat ms", "W lat ms")) + "\n")
	sb.WriteString(sep(w) + "\n")
	if len(rows) == 0 { sb.WriteString(styleDim.Render("  (no data)") + "\n"); return sb.String() }
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-22s  %12.2f  %12.2f  %9.2f  %9.2f\n", trunc(r.Container, 22), r.ReadKBs, r.WriteKBs, r.RLatMs, r.WLatMs))
	}
	return sb.String()
}

func renderNetTable(rows []NetRow, ac lipgloss.Color, w int) string {
	var sb strings.Builder
	sb.WriteString(sectionLabel("▸ M4 Network", ac) + "\n")
	sb.WriteString(styleCol.Render(fmt.Sprintf("  %-22s  %6s  %7s  %9s  %10s  %11s", "Container", "Flows", "ESTABL", "TIM_WAIT", "CLO_WAIT", "Retransmit")) + "\n")
	sb.WriteString(sep(w) + "\n")
	if len(rows) == 0 { sb.WriteString(styleDim.Render("  (no data)") + "\n"); return sb.String() }
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-22s  %6d  %7d  %9d  %10d  %11d\n", trunc(r.Container, 22), r.Flows, r.Established, r.TimeWait, r.CloseWait, r.Retransmits))
	}
	return sb.String()
}

func renderSysTable(rows []SysRow, ac lipgloss.Color, w int) string {
	var sb strings.Builder
	sb.WriteString(sectionLabel("▸ M6 Syscall", ac) + "\n")
	sb.WriteString(styleCol.Render(fmt.Sprintf("  %-22s  %15s  %10s  %10s  %15s", "Container", "Syscall", "Count", "Failures", "Avg Latency(ms)")) + "\n")
	sb.WriteString(sep(w) + "\n")
	if len(rows) == 0 { sb.WriteString(styleDim.Render("  (no data)") + "\n"); return sb.String() }
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-22s  %15s  %10d  %10d  %15.3f\n", trunc(r.Container, 22), trunc(r.SyscallName, 15), r.Count, r.Failures, r.AvgLatMs))
	}
	return sb.String()
}


// ─── Left panel ───────────────────────────────────────────────────────────────



// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	interval       := flag.Duration("interval", 2*time.Second, "poll interval")
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
	flag.Parse()

	cfg := displayConfig{
		containersOnly: *containersOnly,
		topN:           *topN,
		showFiles:      *showFiles,
		showTCP:        *showTCP,
		showSlowSys:    *showSlowSys,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	var (
		cpuColl *collector.CpuCollector
		memColl *collector.MemoryCollector
		ioColl  *collector.IoCollector
		netColl *collector.NetworkCollector
		sysColl *collector.SyscallCollector
	)

	if !*demo {
		resolver, err := cgroup.NewResolver()
		if err != nil {
			logger.Warn("cgroup resolver init failed — IDs only", "err", err)
			resolver = &cgroup.Resolver{}
		}

		// Keep all BPF links alive for the lifetime of the process.
		// Discarding them (using _) caused the probes to detach immediately.
		var allLinks []link.Link

		var cpuLinks []link.Link
		cpuColl, cpuLinks, err = loadCPU(*cpuBPF, resolver, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "M1 CPU init failed: %v\n  Tip: pass --demo for simulated data\n", err)
			os.Exit(1)
		}
		allLinks = append(allLinks, cpuLinks...)

		var memLinks []link.Link
		memColl, memLinks, _ = loadMemory(*memBPF, resolver, logger)
		allLinks = append(allLinks, memLinks...)

		var ioLinks []link.Link
		ioColl, ioLinks, _ = loadIO(*ioBPF, resolver, logger)
		allLinks = append(allLinks, ioLinks...)

		var netLinks []link.Link
		netColl, netLinks, _ = loadNetwork(*netBPF, resolver, logger)
		allLinks = append(allLinks, netLinks...)

		var sysLinks []link.Link
		sysColl, sysLinks, _ = loadSyscall(*sysBPF, resolver, logger)
		allLinks = append(allLinks, sysLinks...)

		// Close all probes after the TUI exits.
		defer closeLinks(allLinks)
	}

	m := newModel(*demo, *interval, cfg, cpuColl, memColl, ioColl, netColl, sysColl)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}
}
