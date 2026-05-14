// Package overview provides the Overview tab — a multi-section summary dashboard
// that mirrors the original main.go card layout, enhanced with per-container
// sparklines that update at the render tick rate from buffered history.
package overview

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/viewport"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/sparkline"
)

const maxHistory = 60 // batches retained for sparklines

// cpuHist tracks sparkline history per container.
type cpuHist struct {
	cpu sparkline.Model
	mem sparkline.Model
}

// View implements views.View for the Overview tab.
type View struct {
	vp       viewport.Model
	batches  []msg.DataBatch
	hists    map[string]*cpuHist // container → sparkline state
	theme    theme.Theme
	w, h     int
	dirty    bool
	cached   string
	follow   bool
	focused  bool
}

func New(th theme.Theme) *View {
	vp := viewport.New(80, 20)
	return &View{
		vp:     vp,
		hists:  make(map[string]*cpuHist),
		follow: true,
		theme:  th,
	}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	v.batches = append(v.batches, batch)
	if len(v.batches) > maxHistory {
		v.batches = v.batches[len(v.batches)-maxHistory:]
	}
	// Update sparklines for each container in this batch.
	for _, s := range batch.CPU {
		h := v.ensureHist(s.ContainerName)
		h.cpu.Push(s.CPUSeconds)
	}
	for _, s := range batch.Mem {
		h := v.ensureHist(s.ContainerName)
		h.mem.Push(float64(s.MemoryBytes) / 1024 / 1024)
	}
	v.dirty = true
	v.cached = ""
}

func (v *View) SetSize(w, h int) {
	v.w, v.h = w, h
	v.vp.Width = w
	v.vp.Height = h - 1 // title row
	v.dirty = true; v.cached = ""
}

func (v *View) SetTheme(th theme.Theme) { v.theme = th; v.dirty = true; v.cached = "" }
func (v *View) Focus()                  { v.focused = true }
func (v *View) Blur()                   { v.focused = false }
func (v *View) StatusLine() string      { return fmt.Sprintf("Overview  [%d batches]  ·  G follow  ·  ↑↓ scroll", len(v.batches)) }
func (v *View) SelectedContainer() string { return "" }

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	if msg, ok := tmsg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "g": v.vp.GotoTop(); v.follow = false
		case "G": v.follow = true
		case "up", "k": v.follow = false; v.vp.LineUp(1)
		case "down", "j": v.vp.LineDown(1)
		case "pgup": v.follow = false; v.vp.HalfViewUp()
		case "pgdown": v.vp.HalfViewDown()
		}
		v.dirty = true
	}
	var cmd tea.Cmd
	v.vp, cmd = v.vp.Update(tmsg)
	return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" { return v.cached }

	var content strings.Builder
	if len(v.batches) == 0 {
		content.WriteString(v.theme.TableDim.Render("  Waiting for first batch…"))
	} else {
		// Latest batch only — show summary cards.
		b := v.batches[len(v.batches)-1]
		content.WriteString(v.renderBatch(b))
	}
	v.vp.SetContent(content.String())
	if v.follow { v.vp.GotoBottom() }

	title := v.theme.PanelTitle.Render(fmt.Sprintf(
		"  ◉ Overview  [%d batches]  %s",
		len(v.batches),
		v.theme.BadgeGreen.Render(" LIVE "),
	))
	v.cached = title + "\n" + v.vp.View()
	v.dirty = false
	return v.cached
}

// ─── Rendering ───────────────────────────────────────────────────────────────

func (v *View) renderBatch(b msg.DataBatch) string {
	var sb strings.Builder
	ts := v.theme.TableDim.Render("  " + b.Timestamp.Format("15:04:05") + "  ")
	sb.WriteString(ts + v.theme.Separator.Render(strings.Repeat("─", v.w-12)) + "\n\n")

	// CPU section.
	sb.WriteString(v.theme.PanelTitle.Render("▸ CPU") + "\n")
	sb.WriteString(v.theme.TableHeader.Render(
		fmt.Sprintf("  %-22s  %-28s  %10s  %9s", "Container", "CPU sparkline", "CPU(s/Δt)", "Threads")) + "\n")
	for _, s := range b.CPU {
		h := v.ensureHist(s.ContainerName)
		spark := h.cpu.View()
		sb.WriteString(fmt.Sprintf("  %-22s  %-28s  %10.4f  %9d\n",
			trunc(s.ContainerName, 22), spark, s.CPUSeconds, s.ThreadCount))
	}
	sb.WriteByte('\n')

	// Mem section.
	sb.WriteString(v.theme.PanelTitle.Render("▸ Memory") + "\n")
	sb.WriteString(v.theme.TableHeader.Render(
		fmt.Sprintf("  %-22s  %-28s  %10s", "Container", "MEM sparkline", "RSS (MB)")) + "\n")
	for _, s := range b.Mem {
		h := v.ensureHist(s.ContainerName)
		spark := h.mem.View()
		sb.WriteString(fmt.Sprintf("  %-22s  %-28s  %10.2f\n",
			trunc(s.ContainerName, 22), spark, float64(s.MemoryBytes)/1024/1024))
	}
	sb.WriteByte('\n')

	// I/O section.
	sb.WriteString(v.theme.PanelTitle.Render("▸ I/O") + "\n")
	sb.WriteString(v.theme.TableHeader.Render(
		fmt.Sprintf("  %-22s  %12s  %12s", "Container", "Read KB/s", "Write KB/s")) + "\n")
	for _, s := range b.IO {
		sb.WriteString(fmt.Sprintf("  %-22s  %12.2f  %12.2f\n",
			trunc(s.ContainerName, 22), s.ReadBytesPerSec/1024, s.WriteBytesPerSec/1024))
	}
	sb.WriteByte('\n')

	return sb.String()
}

func (v *View) ensureHist(container string) *cpuHist {
	h, ok := v.hists[container]
	if !ok {
		sparkW := 24
		h = &cpuHist{
			cpu: sparkline.New("CPU", "s", string(v.theme.Green), sparkW, v.theme),
			mem: sparkline.New("MEM", "MB", string(v.theme.Blue), sparkW, v.theme),
		}
		v.hists[container] = h
	}
	return h
}

func trunc(s string, n int) string {
	for _, pfx := range []string{"docker:", "cri:", "systemd:", "cgroup:", "host:"} {
		s = strings.TrimPrefix(s, pfx)
	}
	runes := []rune(s); if len(runes) <= n { return s }
	return string(runes[:n-1]) + "…"
}

var _ = time.Now
var _ views.View = (*View)(nil)
