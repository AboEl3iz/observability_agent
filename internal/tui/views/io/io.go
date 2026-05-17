// Package ioview provides the I/O tab view.
package ioview

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

type row struct {
	Container string
	ReadKBs   float64
	WriteKBs  float64
	RP95Ms    float64
	RP99Ms    float64
	WP95Ms    float64
	WP99Ms    float64
}

// View implements views.View for the I/O tab.
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
		{Title: "Container", Width: 24, Sortable: true,
			SortLess: func(a, b table.Row) bool { return a.(row).Container < b.(row).Container },
			Format:   func(r table.Row, _ int) string { return trunc(r.(row).Container, 24) },
		},
		{Title: "Read KB/s", Width: 11, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).ReadKBs > b.(row).ReadKBs },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).ReadKBs) },
		},
		{Title: "Write KB/s", Width: 11, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).WriteKBs > b.(row).WriteKBs },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).WriteKBs) },
		},
		{Title: "R p95 ms", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).RP95Ms > b.(row).RP95Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).RP95Ms) },
		},
		{Title: "R p99 ms", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).RP99Ms > b.(row).RP99Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).RP99Ms) },
		},
		{Title: "W p95 ms", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).WP95Ms > b.(row).WP95Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).WP95Ms) },
		},
		{Title: "W p99 ms", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).WP99Ms > b.(row).WP99Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).WP99Ms) },
		},
	}
	return &View{tbl: table.New(cols, th), search: searchbar.New(th), theme: th}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	samples := batch.IO
	sort.Slice(samples, func(i, j int) bool {
		return (samples[i].ReadBytesPerSec + samples[i].WriteBytesPerSec) >
			(samples[j].ReadBytesPerSec + samples[j].WriteBytesPerSec)
	})
	rows := make([]table.Row, 0, len(samples))
	for _, s := range samples {
		rKey := fmt.Sprintf("%s:io_read", s.ContainerName)
		wKey := fmt.Sprintf("%s:io_write", s.ContainerName)
		rSnaps := batch.Percentiles[rKey].W60s
		wSnaps := batch.Percentiles[wKey].W60s

		rows = append(rows, row{
			Container: s.ContainerName,
			ReadKBs:   s.ReadBytesPerSec / 1024,
			WriteKBs:  s.WriteBytesPerSec / 1024,
			RP95Ms:    rSnaps.P95,
			RP99Ms:    rSnaps.P99,
			WP95Ms:    wSnaps.P95,
			WP99Ms:    wSnaps.P99,
		})
	}
	v.tbl.SetRows(rows); v.dirty = true; v.cached = ""
}

func (v *View) SetSize(w, h int)        { v.w, v.h = w, h; v.tbl.SetSize(w, h-2); v.dirty = true; v.cached = "" }
func (v *View) SetTheme(th theme.Theme) { v.theme = th; v.tbl.SetTheme(th); v.search.SetTheme(th); v.dirty = true; v.cached = "" }
func (v *View) Focus()                  { v.focused = true; v.tbl.Focus() }
func (v *View) Blur()                   { v.focused = false; v.tbl.Blur() }
func (v *View) StatusLine() string      { return "M3 I/O  ·  s/S sort  ·  / filter  ·  enter detail" }
func (v *View) SelectedContainer() string {
	r := v.tbl.SelectedRow(); if r == nil { return "" }; return r.(row).Container
}

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	switch msg := tmsg.(type) {
	case tea.KeyMsg:
		if v.search.Visible() {
			switch msg.String() {
			case "esc", "enter":
				v.search.Hide()
				if msg.String() == "esc" { v.search.Reset(); v.tbl.SetFilter("", nil) }
				v.dirty = true; return v, nil
			}
			var cmd tea.Cmd; v.search, cmd = v.search.Update(tmsg)
			v.tbl.SetFilter(v.search.Value(), func(r table.Row, q string) bool {
				return strings.Contains(strings.ToLower(r.(row).Container), strings.ToLower(q))
			}); v.dirty = true; return v, cmd
		}
		if msg.String() == "/" { v.search.Show(); v.dirty = true; return v, nil }
	}
	var cmd tea.Cmd; v.tbl, cmd = v.tbl.Update(tmsg); v.dirty = true; return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" { return v.cached }
	var sb strings.Builder
	sb.WriteString(v.theme.PanelTitle.Render("  ▸ M3 I/O Metrics") + "\n")
	sb.WriteString(v.tbl.View())
	if v.search.Visible() { sb.WriteString("\n" + v.search.View(v.w)) }
	v.cached = sb.String(); v.dirty = false; return v.cached
}

func trunc(s string, n int) string {
	for _, pfx := range []string{"docker:", "cri:", "systemd:", "cgroup:", "host:"} {
		s = strings.TrimPrefix(s, pfx)
	}
	runes := []rune(s); if len(runes) <= n { return s }
	return string(runes[:n-1]) + "…"
}

var _ collector.IoSample
var _ views.View = (*View)(nil)
