// Package netview provides the Network tab view.
package netview

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
	Flows       int
	Established int
	TimeWait    int
	CloseWait   int
	Retransmits int
}

// View implements views.View for the Network tab.
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
		{Title: "Flows", Width: 7, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Flows > b.(row).Flows },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Flows) },
		},
		{Title: "ESTABL", Width: 8, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Established > b.(row).Established },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Established) },
		},
		{Title: "TIM_WAIT", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).TimeWait > b.(row).TimeWait },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).TimeWait) },
		},
		{Title: "CLO_WAIT", Width: 10, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).CloseWait > b.(row).CloseWait },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).CloseWait) },
		},
		{Title: "Retransmit", Width: 11, Sortable: true, Align: "right",
			SortLess: func(a, b table.Row) bool { return a.(row).Retransmits > b.(row).Retransmits },
			Format:   func(r table.Row, _ int) string { return fmt.Sprintf("%d", r.(row).Retransmits) },
		},
	}
	return &View{tbl: table.New(cols, th), search: searchbar.New(th), theme: th}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	sums := batch.Net
	sort.Slice(sums, func(i, j int) bool { return sums[i].ActiveFlows > sums[j].ActiveFlows })
	rows := make([]table.Row, 0, len(sums))
	for _, s := range sums {
		rows = append(rows, row{
			Container:   s.ContainerName,
			Flows:       s.ActiveFlows,
			Established: s.Established,
			TimeWait:    s.TimeWait,
			CloseWait:   s.CloseWait,
			Retransmits: int(s.TotalRetransmits),
		})
	}
	v.tbl.SetRows(rows); v.dirty = true; v.cached = ""
}

func (v *View) SetSize(w, h int)        { v.w, v.h = w, h; v.tbl.SetSize(w, h-2); v.dirty = true; v.cached = "" }
func (v *View) SetTheme(th theme.Theme) { v.theme = th; v.tbl.SetTheme(th); v.search.SetTheme(th); v.dirty = true; v.cached = "" }
func (v *View) Focus()                  { v.focused = true; v.tbl.Focus() }
func (v *View) Blur()                   { v.focused = false; v.tbl.Blur() }
func (v *View) StatusLine() string      { return "M4 Network  ·  s/S sort  ·  / filter  ·  enter detail" }
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
	sb.WriteString(v.theme.PanelTitle.Render("  ▸ M4 Network Metrics") + "\n")
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

var _ collector.NetSummary
var _ views.View = (*View)(nil)
