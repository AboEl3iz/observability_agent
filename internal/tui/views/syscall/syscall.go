// Package syscallview provides the Syscall tab view.
package syscallview

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
	Container   string
	Rank        int
	SyscallName string
	Count       int
	Failures    int
	P50Ms       float64
	P95Ms       float64
	P99Ms       float64
	MaxMs       float64
}

// View implements views.View for the Syscall tab.
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
		{Title: "Rank", Width: 5, Sortable: false, Align: "right",
			Format: func(r table.Row, _ int) string { return fmt.Sprintf("#%d", r.(row).Rank) },
		},
		{Title: "Syscall", Width: 16, Sortable: true,
			SortLess: func(a, b table.Row) bool { return a.(row).SyscallName < b.(row).SyscallName },
			Format:   func(r table.Row, _ int) string { return trunc(r.(row).SyscallName, 16) },
		},
		{Title: "Count", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Count > b.(row).Count },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Count) },
		},
		{Title: "Failures", Width: 9, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Failures > b.(row).Failures },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Failures) },
		},
		{Title: "p50 ms", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).P50Ms > b.(row).P50Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).P50Ms) },
		},
		{Title: "p95 ms", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).P95Ms > b.(row).P95Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).P95Ms) },
		},
		{Title: "p99 ms", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).P99Ms > b.(row).P99Ms },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).P99Ms) },
		},
		{Title: "Max ms", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).MaxMs > b.(row).MaxMs },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%.2f", r.(row).MaxMs) },
		},
	}
	return &View{tbl: table.New(cols, th), search: searchbar.New(th), theme: th}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	sums := batch.Sys
	sort.Slice(sums, func(i, j int) bool {
		if sums[i].ContainerName != sums[j].ContainerName {
			return sums[i].ContainerName < sums[j].ContainerName
		}
		return sums[i].Rank < sums[j].Rank
	})
	rows := make([]table.Row, 0, len(sums))
	for _, s := range sums {
		key := fmt.Sprintf("%s:sys_%d", s.ContainerName, s.SyscallID)
		snaps := batch.Percentiles[key].W60s

		rows = append(rows, row{
			Container:   s.ContainerName,
			Rank:        s.Rank,
			SyscallName: s.SyscallName,
			Count:       int(s.Count),
			Failures:    int(s.Failures),
			P50Ms:       snaps.P50,
			P95Ms:       snaps.P95,
			P99Ms:       snaps.P99,
			MaxMs:       snaps.Max,
		})
	}
	v.tbl.SetRows(rows); v.dirty = true; v.cached = ""
}

func (v *View) SetSize(w, h int)        { v.w, v.h = w, h; v.tbl.SetSize(w, h-2); v.dirty = true; v.cached = "" }
func (v *View) SetTheme(th theme.Theme) { v.theme = th; v.tbl.SetTheme(th); v.search.SetTheme(th); v.dirty = true; v.cached = "" }
func (v *View) Focus()                  { v.focused = true; v.tbl.Focus() }
func (v *View) Blur()                   { v.focused = false; v.tbl.Blur() }
func (v *View) StatusLine() string      { return "M6 Syscalls  ·  s/S sort  ·  / filter  ·  enter detail" }
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
				return strings.Contains(strings.ToLower(r.(row).Container), strings.ToLower(q)) ||
					strings.Contains(strings.ToLower(r.(row).SyscallName), strings.ToLower(q))
			}); v.dirty = true; return v, cmd
		}
		if msg.String() == "/" { v.search.Show(); v.dirty = true; return v, nil }
	}
	var cmd tea.Cmd; v.tbl, cmd = v.tbl.Update(tmsg); v.dirty = true; return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" { return v.cached }
	var sb strings.Builder
	sb.WriteString(v.theme.PanelTitle.Render("  ▸ M6 Syscall Top-5 per Container") + "\n")
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

var _ collector.SyscallSummary
var _ views.View = (*View)(nil)
