// Package detail provides the container observability cockpit — the full
// single-container detail page opened with Enter from any table view.
//
// Sections:
//   A. Header       — name, runtime, uptime, state
//   B. Resources    — current CPU/Mem/IO/Net numbers
//   C. Live Graphs  — 5 sparklines (CPU, Mem, I/O read, I/O write, syscall lat)
//   D. Network      — TCP flows, retransmits
//   E. Syscalls     — top syscalls with failure rates
//   F. Event Timeline — filterable chronological stream
//   G. Actions      — p pause, y yank, e export
package detail

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/searchbar"
	"ebpf/internal/tui/widgets/sparkline"
	"ebpf/pkg/collector"
)

const histCap = 120

// containerHistory holds per-container sparkline ring buffers.
type containerHistory struct {
	cpu    sparkline.Model
	mem    sparkline.Model
	ioRead sparkline.Model
	ioWrt  sparkline.Model
	sysLat sparkline.Model
}

// View implements views.View for the detail / cockpit page.
type View struct {
	container string // currently viewed container
	hist      containerHistory
	lastBatch msg.DataBatch
	events    []msg.Event
	search    searchbar.Model
	filter    string
	vp        viewport.Model
	theme     theme.Theme
	w, h      int
	paused    bool
	dirty     bool
	cached    string
}

func New(th theme.Theme) *View {
	vp := viewport.New(80, 40)
	return &View{
		vp:     vp,
		search: searchbar.New(th),
		theme:  th,
	}
}

// SetContainer selects the container to display and resets history.
func (v *View) SetContainer(name string) {
	if v.container == name {
		return
	}
	v.container = name
	sparkW := 40
	v.hist = containerHistory{
		cpu:    sparkline.New("CPU  ", "s", string(th.Green), sparkW, v.theme),
		mem:    sparkline.New("MEM  ", "MB", string(th.Blue), sparkW, v.theme),
		ioRead: sparkline.New("READ ", "KB/s", string(th.Cyan), sparkW, v.theme),
		ioWrt:  sparkline.New("WRITE", "KB/s", string(th.Orange), sparkW, v.theme),
		sysLat: sparkline.New("SYSLAT", "ms", string(th.Yellow), sparkW, v.theme),
	}
	v.events = nil
	v.dirty = true; v.cached = ""
}

var th theme.Theme // package-level copy set on each SetTheme call

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	if v.paused {
		return
	}
	v.lastBatch = batch
	// Update sparklines for our container.
	for _, s := range batch.CPU {
		if s.ContainerName == v.container {
			v.hist.cpu.Push(s.CPUSeconds)
		}
	}
	for _, s := range batch.Mem {
		if s.ContainerName == v.container {
			v.hist.mem.Push(float64(s.MemoryBytes) / 1024 / 1024)
		}
	}
	for _, s := range batch.IO {
		if s.ContainerName == v.container {
			v.hist.ioRead.Push(s.ReadBytesPerSec / 1024)
			v.hist.ioWrt.Push(s.WriteBytesPerSec / 1024)
		}
	}
	for _, s := range batch.Sys {
		if s.ContainerName == v.container && s.Rank == 1 {
			v.hist.sysLat.Push(s.AvgLatencyMs)
		}
	}
	// Collect container events.
	for _, e := range batch.Events {
		if e.Container == v.container || v.container == "" {
			v.events = append(v.events, e)
		}
	}
	if len(v.events) > 500 {
		v.events = v.events[len(v.events)-500:]
	}
	v.dirty = true; v.cached = ""
}

func (v *View) SetSize(w, h int) {
	v.w, v.h = w, h
	v.vp.Width = w
	v.vp.Height = h - 2
	v.dirty = true; v.cached = ""
}

func (v *View) SetTheme(t theme.Theme) { v.theme = t; th = t; v.search.SetTheme(t); v.dirty = true; v.cached = "" }
func (v *View) Focus()                 {}
func (v *View) Blur()                  {}
func (v *View) StatusLine() string {
	pause := ""
	if v.paused { pause = "  PAUSED" }
	return fmt.Sprintf("Detail: %s%s  ·  Esc back  ·  p pause  ·  / filter  ·  ↑↓ scroll", trunc(v.container, 30), pause)
}
func (v *View) SelectedContainer() string { return "" }

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	switch msg := tmsg.(type) {
	case tea.KeyMsg:
		if v.search.Visible() {
			switch msg.String() {
			case "esc":
				v.search.Hide(); v.search.Reset(); v.filter = ""
				v.dirty = true; return v, nil
			case "enter":
				v.search.Hide(); v.dirty = true; return v, nil
			}
			var cmd tea.Cmd; v.search, cmd = v.search.Update(tmsg)
			v.filter = v.search.Value(); v.dirty = true; return v, cmd
		}
		switch msg.String() {
		case "p":
			v.paused = !v.paused; v.dirty = true
		case "y":
			// TODO: copy container name to clipboard
		case "/":
			v.search.Show(); v.dirty = true
		case "g":
			v.vp.GotoTop()
		case "G":
			v.vp.GotoBottom()
		case "up", "k":
			v.vp.LineUp(1)
		case "down", "j":
			v.vp.LineDown(1)
		case "pgup":
			v.vp.HalfViewUp()
		case "pgdown":
			v.vp.HalfViewDown()
		}
		v.dirty = true
	}
	var cmd tea.Cmd; v.vp, cmd = v.vp.Update(tmsg)
	return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" { return v.cached }
	v.vp.SetContent(v.buildContent())
	title := v.theme.PanelTitle.Render("  ◉ Container Cockpit: " + trunc(v.container, 40))
	v.cached = title + "\n" + v.vp.View()
	v.dirty = false
	return v.cached
}

// ─── Content builder ─────────────────────────────────────────────────────────

func (v *View) buildContent() string {
	var sb strings.Builder
	sep := v.theme.Separator.Render(strings.Repeat("─", v.w))

	// A. Header
	sb.WriteString(v.theme.BadgeBlue.Render(" CONTAINER ") + " " +
		lipgloss.NewStyle().Foreground(v.theme.Fg).Render(v.container) + "\n")
	sb.WriteString(sep + "\n\n")

	// B. Current resource snapshot
	sb.WriteString(v.theme.PanelTitle.Render("▸ Resources") + "\n")
	sb.WriteString(v.renderResources())
	sb.WriteString(sep + "\n\n")

	// C. Live graphs (5 sparklines side by side)
	sb.WriteString(v.theme.PanelTitle.Render("▸ Live Graphs") + "\n")
	sb.WriteString(v.hist.cpu.View() + "\n")
	sb.WriteString(v.hist.mem.View() + "\n")
	sb.WriteString(v.hist.ioRead.View() + "\n")
	sb.WriteString(v.hist.ioWrt.View() + "\n")
	sb.WriteString(v.hist.sysLat.View() + "\n")
	sb.WriteString(sep + "\n\n")

	// D. Network
	sb.WriteString(v.theme.PanelTitle.Render("▸ Network") + "\n")
	sb.WriteString(v.renderNetwork())
	sb.WriteString(sep + "\n\n")

	// E. Syscalls
	sb.WriteString(v.theme.PanelTitle.Render("▸ Top Syscalls") + "\n")
	sb.WriteString(v.renderSyscalls())
	sb.WriteString(sep + "\n\n")

	// F. Event Timeline
	sb.WriteString(v.theme.PanelTitle.Render("▸ Event Timeline") + "\n")
	if v.search.Visible() {
		sb.WriteString(v.search.View(v.w) + "\n")
	}
	sb.WriteString(v.renderEvents())

	return sb.String()
}

func (v *View) renderResources() string {
	b := v.lastBatch
	var sb strings.Builder
	for _, s := range b.CPU {
		if s.ContainerName != v.container { continue }
		sb.WriteString(fmt.Sprintf("  CPU: %.4f s/Δt   Threads: %d   RunQ: %.3f ms   CtxSw: %.0f/s\n",
			s.CPUSeconds, s.ThreadCount, s.RunqLatencySeconds*1000, s.CtxSwitchesPerSec))
	}
	for _, s := range b.Mem {
		if s.ContainerName != v.container { continue }
		lim := "unlimited"
		if s.MemoryLimitBytes > 0 {
			lim = fmt.Sprintf("%.1f MB", float64(s.MemoryLimitBytes)/1024/1024)
		}
		sb.WriteString(fmt.Sprintf("  MEM: %.2f MB   Limit: %s   Faults/s: %.1f\n",
			float64(s.MemoryBytes)/1024/1024, lim, s.FaultsPerSec))
	}
	for _, s := range b.IO {
		if s.ContainerName != v.container { continue }
		sb.WriteString(fmt.Sprintf("  I/O Read: %.2f KB/s   Write: %.2f KB/s   R-lat: %.2f ms   W-lat: %.2f ms\n",
			s.ReadBytesPerSec/1024, s.WriteBytesPerSec/1024, s.AvgReadLatencyMs, s.AvgWriteLatencyMs))
	}
	if sb.Len() == 0 {
		return v.theme.TableDim.Render("  (no data yet)\n")
	}
	return sb.String()
}

func (v *View) renderNetwork() string {
	b := v.lastBatch
	var sb strings.Builder
	for _, s := range b.Net {
		if s.ContainerName != v.container { continue }
		sb.WriteString(fmt.Sprintf("  Flows: %d   Established: %d   TimeWait: %d   CloseWait: %d   Retransmits: %d\n",
			s.ActiveFlows, s.Established, s.TimeWait, s.CloseWait, s.TotalRetransmits))
	}
	if sb.Len() == 0 {
		return v.theme.TableDim.Render("  (no network data)\n")
	}
	return sb.String()
}

func (v *View) renderSyscalls() string {
	b := v.lastBatch
	var sb strings.Builder
	sb.WriteString(v.theme.TableHeader.Render(
		fmt.Sprintf("  %-4s  %-16s  %10s  %9s  %12s\n", "Rank", "Syscall", "Count", "Failures", "Avg Lat ms")))
	for _, s := range b.Sys {
		if s.ContainerName != v.container { continue }
		sb.WriteString(fmt.Sprintf("  #%-3d  %-16s  %10d  %9d  %12.3f\n",
			s.Rank, trunc(s.SyscallName, 16), s.Count, s.Failures, s.AvgLatencyMs))
	}
	if sb.Len() == 0 {
		return v.theme.TableDim.Render("  (no syscall data)\n")
	}
	return sb.String()
}

func (v *View) renderEvents() string {
	var lines []string
	for _, e := range v.events {
		if v.filter != "" &&
			!strings.Contains(strings.ToLower(e.Message), strings.ToLower(v.filter)) {
			continue
		}
		ts := v.theme.TableDim.Render(e.At.Format("15:04:05"))
		styled := v.styledMsg(e)
		lines = append(lines, ts+" "+styled)
	}
	if len(lines) == 0 {
		return v.theme.TableDim.Render("  No events.\n")
	}
	return strings.Join(lines, "\n") + "\n"
}

func (v *View) styledMsg(e msg.Event) string {
	switch e.Kind {
	case msg.EventKindTCP: return v.theme.EventTCP.Render(e.Message)
	case msg.EventKindError: return v.theme.EventError.Render(e.Message)
	case msg.EventKindOOM: return v.theme.EventOOM.Render(e.Message)
	case msg.EventKindSlowSys: return v.theme.EventSlowSys.Render(e.Message)
	default: return v.theme.EventInfo.Render(e.Message)
	}
}

func trunc(s string, n int) string {
	for _, pfx := range []string{"docker:", "cri:", "systemd:", "cgroup:", "host:"} {
		s = strings.TrimPrefix(s, pfx)
	}
	runes := []rune(s); if len(runes) <= n { return s }
	return string(runes[:n-1]) + "…"
}

// Silence unused import warnings.
var _ = time.Now
var _ collector.CpuSample
var _ views.View = (*View)(nil)
