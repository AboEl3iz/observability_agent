// Package table provides VirtualTable — a high-performance, selectable,
// sortable, filterable table widget that renders only the visible rows.
//
// O(visible) rendering means it handles 10,000+ rows with no perceptible
// latency, making it suitable for high-frequency eBPF event tables.
package table

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/keys"
	"ebpf/internal/tui/theme"
)

// ─── Column ───────────────────────────────────────────────────────────────────

// Column describes one column of the table.
type Column struct {
	Title    string
	Width    int
	Sortable bool
	// SortLess compares two rows; return true if row[i] < row[j].
	SortLess func(a, b Row) bool
	// Format renders the cell value for this column at index col.
	Format func(r Row, col int) string
	// Align is "left" (default) or "right".
	Align string
}

// ─── Row ──────────────────────────────────────────────────────────────────────

// Row is a type-erased table row.  Concrete view packages define their own
// named row type and cast here, so the widget stays generic.
type Row interface{}

// ─── Model ────────────────────────────────────────────────────────────────────

// Model is the VirtualTable widget state.
type Model struct {
	columns []Column
	rows    []Row    // full data set
	visible []int    // indices into rows after filtering
	cursor  int      // index in visible[]
	offset  int      // first visible row index in visible[]
	sortCol int      // column index; -1 = unsorted
	sortAsc bool
	filter  string
	filterFn func(r Row, q string) bool

	width, height int
	focused       bool
	theme         theme.Theme
}

// New constructs a Model.
func New(cols []Column, th theme.Theme) Model {
	return Model{
		columns: cols,
		sortCol: -1,
		sortAsc: true,
		theme:   th,
	}
}

// ─── Data ─────────────────────────────────────────────────────────────────────

// SetRows replaces the full row set and re-applies the current filter.
func (m *Model) SetRows(rows []Row) {
	m.rows = rows
	m.reindex()
	// Clamp cursor.
	if m.cursor >= len(m.visible) {
		m.cursor = max(0, len(m.visible)-1)
	}
}

// SetFilter sets the filter string and re-indexes.
func (m *Model) SetFilter(q string, fn func(r Row, q string) bool) {
	m.filter = q
	m.filterFn = fn
	m.cursor = 0
	m.offset = 0
	m.reindex()
}

// SetSize updates the widget's render dimensions.
func (m *Model) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// SetTheme swaps the theme at runtime.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// Focus / Blur control keyboard routing.
func (m *Model) Focus() { m.focused = true }
func (m *Model) Blur()  { m.focused = false }

// SelectedRow returns the currently highlighted row, or nil.
func (m Model) SelectedRow() Row {
	if len(m.visible) == 0 {
		return nil
	}
	return m.rows[m.visible[m.cursor]]
}

// ─── Update ───────────────────────────────────────────────────────────────────

// Update handles keyboard input when the table is focused.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.focused {
		return m, nil
	}
	km := keys.Table
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, km.Up):
			m.moveUp(1)
		case key.Matches(msg, km.Down):
			m.moveDown(1)
		case key.Matches(msg, km.PageUp):
			m.moveUp(m.bodyH())
		case key.Matches(msg, km.PageDown):
			m.moveDown(m.bodyH())
		case key.Matches(msg, km.Top):
			m.cursor = 0
			m.offset = 0
		case key.Matches(msg, km.Bottom):
			m.cursor = max(0, len(m.visible)-1)
			m.scrollToCursor()
		case key.Matches(msg, km.SortNext):
			m.cycleSort(true)
		case key.Matches(msg, km.SortPrev):
			m.cycleSort(false)
		}
	}
	return m, nil
}

// ─── View ─────────────────────────────────────────────────────────────────────

// View renders the table for a (width, height) region.
func (m Model) View() string {
	if m.width == 0 {
		return ""
	}
	var sb strings.Builder

	// Header row
	sb.WriteString(m.renderHeader())
	sb.WriteByte('\n')

	// Separator
	sb.WriteString(m.theme.Separator.Render(strings.Repeat("─", m.width)))
	sb.WriteByte('\n')

	bodyH := m.bodyH()
	start := m.offset
	end := start + bodyH
	if end > len(m.visible) {
		end = len(m.visible)
	}

	for i := start; i < end; i++ {
		row := m.rows[m.visible[i]]
		line := m.renderRow(row, i)
		if i == m.cursor && m.focused {
			sb.WriteString(m.theme.TableSelected.Width(m.width).Render(line))
		} else if (i-start)%2 == 1 {
			sb.WriteString(m.theme.TableAltRow.Width(m.width).Render(line))
		} else {
			sb.WriteString(m.theme.TableRow.Width(m.width).Render(line))
		}
		sb.WriteByte('\n')
	}

	// Pad empty rows to fill height.
	for i := end - start; i < bodyH; i++ {
		sb.WriteString(strings.Repeat(" ", m.width))
		sb.WriteByte('\n')
	}

	// Scroll indicator
	if len(m.visible) > bodyH {
		pct := 0
		if len(m.visible) > 0 {
			pct = (m.cursor * 100) / len(m.visible)
		}
		indicator := m.theme.TableDim.Render(
			strings.Repeat("─", m.width-8) +
				lipgloss.NewStyle().Foreground(m.theme.FgDim).Render(
					" " + itoa(pct) + "% ",
				),
		)
		sb.WriteString(indicator)
	}

	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (m Model) bodyH() int {
	h := m.height - 2 // header + separator
	if h < 1 {
		h = 1
	}
	return h
}

func (m *Model) moveUp(n int) {
	m.cursor -= n
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.scrollToCursor()
}

func (m *Model) moveDown(n int) {
	m.cursor += n
	if m.cursor >= len(m.visible) {
		m.cursor = max(0, len(m.visible)-1)
	}
	m.scrollToCursor()
}

func (m *Model) scrollToCursor() {
	bh := m.bodyH()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+bh {
		m.offset = m.cursor - bh + 1
	}
}

func (m *Model) cycleSort(nextCol bool) {
	// Find next sortable column.
	start := m.sortCol
	for i := 0; i < len(m.columns); i++ {
		idx := start + 1
		if nextCol {
			idx = (start + 1 + i) % len(m.columns)
		} else {
			if m.sortCol == start && m.sortAsc {
				m.sortAsc = false
				m.reindex()
				return
			}
		}
		if m.columns[idx].Sortable {
			m.sortCol = idx
			m.sortAsc = true
			m.reindex()
			return
		}
	}
}

func (m *Model) reindex() {
	m.visible = m.visible[:0]
	for i, r := range m.rows {
		if m.filter == "" || m.filterFn == nil || m.filterFn(r, m.filter) {
			m.visible = append(m.visible, i)
		}
	}
	// Sort visible slice.
	if m.sortCol >= 0 && m.sortCol < len(m.columns) && m.columns[m.sortCol].Sortable {
		less := m.columns[m.sortCol].SortLess
		sortRows(m.rows, m.visible, less, m.sortAsc)
	}
}

func (m Model) renderHeader() string {
	var parts []string
	for i, col := range m.columns {
		title := col.Title
		if i == m.sortCol {
			if m.sortAsc {
				title += " ▲"
			} else {
				title += " ▼"
			}
		}
		parts = append(parts, padOrTrunc(title, col.Width, col.Align))
	}
	return m.theme.TableHeader.Render(strings.Join(parts, " "))
}

func (m Model) renderRow(r Row, idx int) string {
	var parts []string
	for i, col := range m.columns {
		cell := ""
		if col.Format != nil {
			cell = col.Format(r, i)
		}
		parts = append(parts, padOrTrunc(cell, col.Width, col.Align))
	}
	return strings.Join(parts, " ")
}

// ─── Sort helper (insertion sort — fast for small N) ─────────────────────────

func sortRows(rows []Row, indices []int, less func(a, b Row) bool, asc bool) {
	for i := 1; i < len(indices); i++ {
		for j := i; j > 0; j-- {
			a, b := rows[indices[j-1]], rows[indices[j]]
			swap := less(b, a)
			if !asc {
				swap = less(a, b)
			}
			if swap {
				indices[j-1], indices[j] = indices[j], indices[j-1]
			} else {
				break
			}
		}
	}
}

// ─── String helpers ──────────────────────────────────────────────────────────

func padOrTrunc(s string, w int, align string) string {
	runes := []rune(s)
	if len(runes) > w {
		if w > 1 {
			return string(runes[:w-1]) + "…"
		}
		return string(runes[:w])
	}
	pad := w - len(runes)
	if align == "right" {
		return strings.Repeat(" ", pad) + s
	}
	return s + strings.Repeat(" ", pad)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// key package alias to avoid stutter.
var key = struct {
	Matches func(msg tea.KeyMsg, b interface{ Keys() []string }) bool
}{
	Matches: func(msg tea.KeyMsg, b interface{ Keys() []string }) bool {
		for _, k := range b.Keys() {
			if msg.String() == k {
				return true
			}
		}
		return false
	},
}
