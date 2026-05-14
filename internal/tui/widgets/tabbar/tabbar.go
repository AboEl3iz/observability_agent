// Package tabbar provides the top navigation tab strip.
package tabbar

import (
	"strings"

	"ebpf/internal/tui/theme"
)

// Tab is a single navigation entry.
type Tab struct {
	Title string // display label
	Key   string // keyboard shortcut hint (e.g. "1")
}

// Model holds the tabbar state.
type Model struct {
	tabs   []Tab
	active int
	width  int
	theme  theme.Theme
}

// New creates a Model with the given tabs.
func New(tabs []Tab, th theme.Theme) Model {
	return Model{tabs: tabs, theme: th}
}

// SetActive sets the active tab index (clamped).
func (m *Model) SetActive(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(m.tabs) {
		i = len(m.tabs) - 1
	}
	m.active = i
}

// Active returns the current active tab index.
func (m Model) Active() int { return m.active }

// Next cycles to the next tab, wrapping around.
func (m *Model) Next() { m.SetActive((m.active + 1) % len(m.tabs)) }

// Prev cycles to the previous tab, wrapping around.
func (m *Model) Prev() { m.SetActive((m.active - 1 + len(m.tabs)) % len(m.tabs)) }

// SetWidth updates the render width.
func (m *Model) SetWidth(w int) { m.width = w }

// SetTheme swaps the theme.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// View renders the tab bar as a single line.
func (m Model) View() string {
	var parts []string
	for i, t := range m.tabs {
		label := " " + t.Title + " "
		if t.Key != "" {
			label = " " + t.Key + ":" + t.Title + " "
		}
		if i == m.active {
			parts = append(parts, m.theme.TabActive.Render(label))
		} else {
			parts = append(parts, m.theme.TabInactive.Render(label))
		}
	}
	bar := strings.Join(parts, "")
	// Pad to full width with the tab bar background.
	pad := m.width - len([]rune(stripAnsi(bar)))
	if pad > 0 {
		bar += m.theme.TabBar.Render(strings.Repeat(" ", pad))
	}
	return bar
}

// stripAnsi is a quick ANSI escape stripper for width calculation.
func stripAnsi(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case !inEsc:
			out.WriteRune(r)
		}
	}
	return out.String()
}
