// Package graphs provides the Graphs tab — a scrollable page of per-container
// sparklines (CPU, Mem, I/O Read, I/O Write, Net flows).
//
// Memory contract: capped at maxContainers entries.  Each entry owns 5
// sparklines with a 120-sample ring buffer (float64 = 8 B each), so the
// absolute worst-case resident size is:
//   50 containers × 5 sparklines × 120 samples × 8 B = 240 KB
//
// Data arrives via SetData which is called on every DataMsg; no goroutines
// are spawned here — the view is purely reactive.
package graphs

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/sparkline"
)

const (
	maxContainers = 50  // evict oldest after this to bound memory
	sparkCap      = 120 // ring-buffer depth per sparkline
)

// containerGraphs holds the five sparklines for one container.
type containerGraphs struct {
	cpu    sparkline.Model
	mem    sparkline.Model
	ioRead sparkline.Model
	ioWrt  sparkline.Model
	net    sparkline.Model
	// seen tracks insertion order so we can evict the oldest container.
	seq int
}

// View implements views.View for the Graphs tab.
type View struct {
	vp      viewport.Model
	graphs  map[string]*containerGraphs // keyed by container name
	order   []string                    // insertion order (for eviction)
	seq     int                         // monotonic counter
	theme   theme.Theme
	label   lipgloss.Style // container-name label style
	w, h    int
	dirty   bool
	cached  string
	focused bool
}

// New constructs an empty Graphs view.
func New(th theme.Theme) *View {
	vp := viewport.New(80, 20)
	return &View{
		vp:     vp,
		graphs: make(map[string]*containerGraphs),
		theme:  th,
		label:  buildLabelStyle(th),
	}
}

func buildLabelStyle(th theme.Theme) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(th.Cyan).Bold(true)
}

// ─── views.View interface ─────────────────────────────────────────────────────

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	// CPU
	for _, s := range batch.CPU {
		g := v.getOrCreate(s.ContainerName)
		g.cpu.Push(s.CPUSeconds)
	}
	// Memory (bytes → MB)
	for _, s := range batch.Mem {
		g := v.getOrCreate(s.ContainerName)
		g.mem.Push(float64(s.MemoryBytes) / 1024 / 1024)
	}
	// I/O (bytes/s → KB/s)
	for _, s := range batch.IO {
		g := v.getOrCreate(s.ContainerName)
		g.ioRead.Push(s.ReadBytesPerSec / 1024)
		g.ioWrt.Push(s.WriteBytesPerSec / 1024)
	}
	// Network (active flows)
	for _, s := range batch.Net {
		g := v.getOrCreate(s.ContainerName)
		g.net.Push(float64(s.ActiveFlows))
	}
	v.dirty = true
	v.cached = ""
}

func (v *View) SetSize(w, h int) {
	v.w, v.h = w, h
	v.vp.Width = w
	v.vp.Height = h - 2 // title row + bottom padding
	// Resize all sparklines to use the available width.
	sparkW := w - 2
	if sparkW < 20 {
		sparkW = 20
	}
	for _, g := range v.graphs {
		g.cpu.SetWidth(sparkW)
		g.mem.SetWidth(sparkW)
		g.ioRead.SetWidth(sparkW)
		g.ioWrt.SetWidth(sparkW)
		g.net.SetWidth(sparkW)
	}
	v.dirty = true
	v.cached = ""
}

func (v *View) SetTheme(th theme.Theme) {
	v.theme = th
	v.label = buildLabelStyle(th)
	for _, g := range v.graphs {
		g.cpu.SetTheme(th)
		g.mem.SetTheme(th)
		g.ioRead.SetTheme(th)
		g.ioWrt.SetTheme(th)
		g.net.SetTheme(th)
	}
	v.dirty = true
	v.cached = ""
}

func (v *View) Focus()  { v.focused = true }
func (v *View) Blur()   { v.focused = false }

func (v *View) StatusLine() string {
	return fmt.Sprintf("Graphs [%d containers]  ·  ↑↓ scroll  ·  g top  ·  G bottom", len(v.graphs))
}

func (v *View) SelectedContainer() string { return "" }

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	if km, ok := tmsg.(tea.KeyMsg); ok {
		switch km.String() {
		case "g":
			v.vp.GotoTop()
			return v, nil
		case "G":
			v.vp.GotoBottom()
			return v, nil
		case "up", "k":
			v.vp.LineUp(1)
			return v, nil
		case "down", "j":
			v.vp.LineDown(1)
			return v, nil
		case "pgup":
			v.vp.HalfViewUp()
			return v, nil
		case "pgdown":
			v.vp.HalfViewDown()
			return v, nil
		}
	}
	var cmd tea.Cmd
	v.vp, cmd = v.vp.Update(tmsg)
	return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" {
		return v.cached
	}
	v.vp.SetContent(v.buildContent())
	title := v.theme.PanelTitle.Render(
		fmt.Sprintf("  ▸ System Graphs  [%d containers]", len(v.graphs)),
	)
	v.cached = title + "\n" + v.vp.View()
	v.dirty = false
	return v.cached
}

// ─── Internal ────────────────────────────────────────────────────────────────

// getOrCreate returns the containerGraphs for name, creating it if absent.
// Evicts the oldest entry when the cap is reached.
func (v *View) getOrCreate(name string) *containerGraphs {
	if name == "" {
		name = "<host>"
	}
	if g, ok := v.graphs[name]; ok {
		return g
	}
	// Evict oldest if at cap.
	if len(v.graphs) >= maxContainers {
		oldest := v.order[0]
		v.order = v.order[1:]
		delete(v.graphs, oldest)
	}
	sparkW := v.w - 2
	if sparkW < 20 {
		sparkW = 20
	}
	th := v.theme
	v.seq++
	g := &containerGraphs{
		cpu:    sparkline.New("CPU  ", "s",     string(th.Green),  sparkW, th),
		mem:    sparkline.New("MEM  ", "MB",    string(th.Blue),   sparkW, th),
		ioRead: sparkline.New("READ ", "KB/s",  string(th.Cyan),   sparkW, th),
		ioWrt:  sparkline.New("WRITE", "KB/s",  string(th.Orange), sparkW, th),
		net:    sparkline.New("NET  ", "flows", string(th.Magenta),sparkW, th),
		seq:    v.seq,
	}
	v.graphs[name] = g
	v.order = append(v.order, name)
	return g
}

func (v *View) buildContent() string {
	if len(v.graphs) == 0 {
		return v.theme.TableDim.Render("  Waiting for container data…")
	}

	sep := v.theme.Separator.Render(strings.Repeat("─", v.w))
	var sb strings.Builder

	for _, name := range v.order {
		g, ok := v.graphs[name]
		if !ok {
			continue
		}
		// Container header
		sb.WriteString("  ")
		sb.WriteString(v.theme.BadgeBlue.Render(" ◉ "))
		sb.WriteString(" ")
		sb.WriteString(v.label.Render(name))
		sb.WriteString("\n")

		// Five sparklines, each indented two spaces
		sb.WriteString("  " + g.cpu.View() + "\n")
		sb.WriteString("  " + g.mem.View() + "\n")
		sb.WriteString("  " + g.ioRead.View() + "\n")
		sb.WriteString("  " + g.ioWrt.View() + "\n")
		sb.WriteString("  " + g.net.View() + "\n")

		sb.WriteString(sep + "\n")
	}
	return sb.String()
}

// Ensure interface compliance at compile time.
var _ views.View = (*View)(nil)
