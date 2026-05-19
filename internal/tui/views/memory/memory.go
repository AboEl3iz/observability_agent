// Package memory provides the Memory tab view.
package memory

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
	"ebpf/pkg/collector"
)

// row holds all per-container memory metrics displayed in the table.
type row struct {
	Container string
	// Memory sizes (MB)
	VirtMB   float64
	RSSMb    float64
	PSSMb    float64
	SharedMB float64
	LimitMb  string
	// Fault rates
	FaultsSec float64
	MajorSec  float64
	MinorSec  float64
	// PSI pressure
	PSISome float64
	PSIFull float64
	// TLB miss rate proxy (minor faults/s)
	TLBMiss float64
}

// View implements views.View for the Memory tab.
type View struct {
	tbl     table.Model
	search  searchbar.Model
	theme   theme.Theme
	w, h    int
	dirty   bool
	cached  string
	focused bool
}

func New(th theme.Theme) *View {
	cols := []table.Column{
		{Title: "Container", Width: 22, Sortable: true,
			SortLess: func(a, b table.Row) bool { return a.(row).Container < b.(row).Container },
			Format:   func(r table.Row, _ int) string { return trunc(r.(row).Container, 22) },
		},
		{Title: "VIRT(MB)", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).VirtMB > b.(row).VirtMB },
			Format:   func(r table.Row, _ int) string { return fmtMBOpt(r.(row).VirtMB) },
		},
		{Title: "RSS(MB)", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).RSSMb > b.(row).RSSMb },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).RSSMb) },
		},
		{Title: "PSS(MB)", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).PSSMb > b.(row).PSSMb },
			Format:   func(r table.Row, _ int) string { return fmtMBOpt(r.(row).PSSMb) },
		},
		{Title: "Shared(MB)", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).SharedMB > b.(row).SharedMB },
			Format:   func(r table.Row, _ int) string { return fmtMBOpt(r.(row).SharedMB) },
		},
		{Title: "Limit(MB)", Width: 10, Sortable: false, Align: "right",
			Format: func(r table.Row, _ int) string { return r.(row).LimitMb },
		},
		{Title: "Faults/s", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).FaultsSec > b.(row).FaultsSec },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.1f", r.(row).FaultsSec) },
		},
		{Title: "Maj/s", Width: 7, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).MajorSec > b.(row).MajorSec },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.1f", r.(row).MajorSec) },
		},
		{Title: "Min/s", Width: 7, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).MinorSec > b.(row).MinorSec },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.1f", r.(row).MinorSec) },
		},
		{Title: "PSI some%", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).PSISome > b.(row).PSISome },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).PSISome) },
		},
		{Title: "PSI full%", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).PSIFull > b.(row).PSIFull },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).PSIFull) },
		},
		{Title: "TLBMiss/s", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).TLBMiss > b.(row).TLBMiss },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.1f", r.(row).TLBMiss) },
		},
	}
	return &View{tbl: table.New(cols, th), search: searchbar.New(th), theme: th}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	samples := batch.Mem
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].MemoryBytes > samples[j].MemoryBytes
	})
	rows := make([]table.Row, 0, len(samples))
	for _, s := range samples {
		lim := "unlimited"
		if s.MemoryLimitBytes > 0 {
			lim = fmt.Sprintf("%.1f", float64(s.MemoryLimitBytes)/1024/1024)
		}
		rows = append(rows, row{
			Container: s.ContainerName,
			VirtMB:    float64(s.VirtBytes) / 1024 / 1024,
			RSSMb:     float64(s.MemoryBytes) / 1024 / 1024,
			PSSMb:     float64(s.PSSBytes) / 1024 / 1024,
			SharedMB:  float64(s.SharedBytes) / 1024 / 1024,
			LimitMb:   lim,
			FaultsSec: s.FaultsPerSec,
			MajorSec:  s.MajorPerSec,
			MinorSec:  s.MinorPerSec,
			PSISome:   s.PSISome,
			PSIFull:   s.PSIFull,
			TLBMiss:   s.TLBMissRate,
		})
	}
	v.tbl.SetRows(rows)
	v.dirty = true
	v.cached = ""
}

func (v *View) SetSize(w, h int) { v.w, v.h = w, h; v.tbl.SetSize(w, h-2); v.dirty = true; v.cached = "" }
func (v *View) SetTheme(th theme.Theme) {
	v.theme = th; v.tbl.SetTheme(th); v.search.SetTheme(th); v.dirty = true; v.cached = ""
}
func (v *View) Focus() { v.focused = true; v.tbl.Focus() }
func (v *View) Blur()  { v.focused = false; v.tbl.Blur() }
func (v *View) StatusLine() string {
	return "M2 Memory  ·  s/S sort  ·  / filter  ·  enter detail  ·  PSI=pressure  ·  TLBMiss/s≈minFaults/s"
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
			v.tbl.SetFilter(v.search.Value(), func(r table.Row, q string) bool {
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
	var sb strings.Builder
	sb.WriteString(v.theme.PanelTitle.Render("  ▸ M2 Memory Metrics") + "\n")
	sb.WriteString(v.tbl.View())
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

// fmtMBOpt formats a MB float64. Returns "—" when the value is 0
// (indicating the metric is unavailable, e.g. --rich-mem not set).
func fmtMBOpt(mb float64) string {
	if mb == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f", mb)
}

// Silence unused import.
var _ collector.MemSample

var _ views.View = (*View)(nil)
