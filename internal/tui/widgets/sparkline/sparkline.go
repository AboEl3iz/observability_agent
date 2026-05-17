// Package sparkline provides a compact terminal sparkline/graph widget backed
// by a fixed-size ring buffer.  It renders using Unicode block characters so
// it is purely text-based with zero image dependencies.
package sparkline

import (
	"fmt"
	"strings"

	"ebpf/internal/tui/theme"
)

// bars is ordered from shortest to tallest block character.
var bars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const defaultCap = 120 // number of samples retained

// Model is the sparkline widget state.
type Model struct {
	data    []float64 // ring buffer contents (oldest → newest)
	head    int       // write head in the ring
	size    int       // number of valid samples
	cap     int       // ring buffer capacity
	peak    float64   // rolling maximum for normalisation
	label   string
	unit    string
	color   string // lipgloss-compatible color hex
	width   int
	theme   theme.Theme
}

// New creates a Model with the given label, display width, and hex color.
func New(label, unit, color string, width int, th theme.Theme) Model {
	cap := defaultCap
	if width > cap {
		cap = width
	}
	return Model{
		data:  make([]float64, cap),
		cap:   cap,
		label: label,
		unit:  unit,
		color: color,
		width: width,
		theme: th,
	}
}

// Push adds a new sample, evicting the oldest when the buffer is full.
func (m *Model) Push(v float64) {
	m.data[m.head] = v
	m.head = (m.head + 1) % m.cap
	if m.size < m.cap {
		m.size++
	}
	// Recompute peak lazily.
	m.peak = 0
	for _, d := range m.values() {
		if d > m.peak {
			m.peak = d
		}
	}
}

// Latest returns the most recently pushed value (0 if empty).
func (m Model) Latest() float64 {
	if m.size == 0 {
		return 0
	}
	idx := (m.head - 1 + m.cap) % m.cap
	return m.data[idx]
}

// View renders the sparkline as a single text line.
// Format:  label  ▁▂▃▄▅▆▇█▇▆  12.34 unit
func (m Model) View() string {
	vals := m.values()

	// The format string is: "%-8s %s %6.1f %s"
	// Fixed characters: 8 (label) + 1 (space) + 1 (space) + 6 (float) + 1 (space) = 17
	fixedW := 17 + len(m.unit)
	graphW := m.width - fixedW
	if graphW < 4 {
		graphW = 4
	}
	if len(vals) > graphW {
		vals = vals[len(vals)-graphW:]
	}

	peak := m.peak
	if peak == 0 {
		peak = 1
	}

	var spark strings.Builder
	for _, v := range vals {
		idx := int((v / peak) * float64(len(bars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(bars) {
			idx = len(bars) - 1
		}
		spark.WriteRune(bars[idx])
	}

	// Right-pad with spaces so the graph is exactly graphW wide.
	// This ensures the graph grows left-to-right but the numbers stay pinned to the right edge.
	padCount := graphW - len(vals)
	if padCount > 0 {
		spark.WriteString(strings.Repeat(" ", padCount))
	}

	latest := m.Latest()
	graph := m.theme.SparkBar.Foreground(m.theme.Cyan).Render(spark.String())

	return fmt.Sprintf("%-8s %s %6.1f %s",
		m.label,
		graph,
		latest,
		m.unit,
	)
}

// SetTheme swaps the theme at runtime.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// SetWidth adjusts the render width.
func (m *Model) SetWidth(w int) { m.width = w }

// ─── Internal ────────────────────────────────────────────────────────────────

// values returns the samples in oldest-first order.
func (m Model) values() []float64 {
	if m.size == 0 {
		return nil
	}
	out := make([]float64, m.size)
	start := (m.head - m.size + m.cap) % m.cap
	for i := 0; i < m.size; i++ {
		out[i] = m.data[(start+i)%m.cap]
	}
	return out
}
