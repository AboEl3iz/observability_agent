// Package cpu provides the CPU tab view — a sortable VirtualTable of
// per-container CPU metrics backed by live eBPF collector data.
package cpu

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/searchbar"
	"ebpf/internal/tui/widgets/table"
	
)

// row is the typed row used by this view's VirtualTable.
type row struct {
	Container  string
	CPUSec     float64
	RunqMs     float64
	CtxPerSec  float64
	Threads    int
	NUMALoc    float64 // % NUMA-local scheduling
	NUMARemote float64 // % NUMA-remote (cross-NUMA migrations)
}

// View implements views.View for the CPU tab.
type View struct {
	tbl    table.Model
	search searchbar.Model
	theme  theme.Theme
	w, h   int
	dirty  bool
	cached string
	focused bool
}

// New constructs the CPU view.
func New(th theme.Theme) *View {
	cols := []table.Column{
		{Title: "Container", Width: 24, Sortable: true,
			SortLess: func(a, b table.Row) bool {
				return a.(row).Container < b.(row).Container
			},
			Format: func(r table.Row, _ int) string { return trunc(r.(row).Container, 24) },
		},
		{Title: "CPU(s/Δt)", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).CPUSec > b.(row).CPUSec },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.4f", r.(row).CPUSec) },
		},
		{Title: "RunQ lat ms", Width: 12, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).RunqMs > b.(row).RunqMs },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.3f", r.(row).RunqMs) },
		},
		{Title: "ctx-sw/s", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).CtxPerSec > b.(row).CtxPerSec },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.1f", r.(row).CtxPerSec) },
		},
		{Title: "Threads", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Threads > b.(row).Threads },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Threads) },
		},
		{Title: "NUMA Loc%", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).NUMALoc > b.(row).NUMALoc },
			Format: func(r table.Row, _ int) string {
				if r.(row).NUMALoc == 0 && r.(row).NUMARemote == 0 {
					return "—"
				}
				return fmt.Sprintf("%.1f", r.(row).NUMALoc)
			},
		},
		{Title: "NUMA Rem%", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).NUMARemote > b.(row).NUMARemote },
			Format: func(r table.Row, _ int) string {
				if r.(row).NUMALoc == 0 && r.(row).NUMARemote == 0 {
					return "—"
				}
				return fmt.Sprintf("%.1f", r.(row).NUMARemote)
			},
		},
	}
	v := &View{
		tbl:    table.New(cols, th),
		search: searchbar.New(th),
		theme:  th,
	}
	return v
}

// ─── views.View interface ─────────────────────────────────────────────────────

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	samples := batch.CPU
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].CPUSeconds > samples[j].CPUSeconds
	})
	rows := make([]table.Row, 0, len(samples))
	for _, s := range samples {
		rows = append(rows, row{
			Container:  s.ContainerName,
			CPUSec:     s.CPUSeconds,
			RunqMs:     s.RunqLatencySeconds * 1000,
			CtxPerSec:  s.CtxSwitchesPerSec,
			Threads:    int(s.ThreadCount),
			NUMALoc:    s.NUMALocalPct,
			NUMARemote: s.NUMARemotePct,
		})
	}
	v.tbl.SetRows(rows)
	v.dirty = true
	v.cached = ""
}

func (v *View) SetSize(w, h int) {
	v.w, v.h = w, h
	v.tbl.SetSize(w, h-2)
	v.dirty = true
	v.cached = ""
}

func (v *View) SetTheme(th theme.Theme) {
	v.theme = th
	v.tbl.SetTheme(th)
	v.search.SetTheme(th)
	v.dirty = true
	v.cached = ""
}

func (v *View) Focus() { v.focused = true; v.tbl.Focus() }
func (v *View) Blur()  { v.focused = false; v.tbl.Blur() }

func (v *View) StatusLine() string {
	return "M1 CPU  ·  s/S sort  ·  / filter  ·  enter detail  ·  NUMA=cpu.stat migrations proxy"
}

func (v *View) SelectedContainer() string {
	r := v.tbl.SelectedRow()
	if r == nil {
		return ""
	}
	return r.(row).Container
}

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	switch msg := tmsg.(type) {
	case tea.KeyMsg:
		if v.search.Visible() {
			switch msg.String() {
			case "esc", "enter":
				v.search.Hide()
				if msg.String() == "esc" {
					v.search.Reset()
					v.tbl.SetFilter("", nil)
				}
				v.dirty = true
				return v, nil
			}
			var cmd tea.Cmd
			v.search, cmd = v.search.Update(tmsg)
			q := v.search.Value()
			v.tbl.SetFilter(q, func(r table.Row, q string) bool {
				return strings.Contains(strings.ToLower(r.(row).Container), strings.ToLower(q))
			})
			v.dirty = true
			return v, cmd
		}
		if msg.String() == "/" {
			v.search.Show()
			v.dirty = true
			return v, nil
		}
	}
	var cmd tea.Cmd
	v.tbl, cmd = v.tbl.Update(tmsg)
	v.dirty = true
	return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" {
		return v.cached
	}
	title := v.theme.PanelTitle.Render("  ▸ M1 CPU Metrics")
	body := v.tbl.View()
	var sb strings.Builder
	sb.WriteString(title + "\n")
	sb.WriteString(body)
	if v.search.Visible() {
		sb.WriteString("\n" + v.search.View(v.w))
	}
	v.cached = sb.String()
	v.dirty = false
	return v.cached
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func trunc(s string, n int) string {
	for _, pfx := range []string{"docker:", "cri:", "systemd:", "cgroup:", "host:"} {
		s = strings.TrimPrefix(s, pfx)
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

// Ensure View satisfies the interface at compile time.
var _ views.View = (*View)(nil)
