// Package statusbar renders the bottom chrome line with key hints and
// live statistics.
package statusbar

import (
	"fmt"
	"strings"

	"ebpf/internal/tui/theme"
)

// Model holds the status bar state.
type Model struct {
	// Left side — key hint string (built from keys.ShortHelp).
	keyHints string
	// Right side — live stats string.
	stats string
	// Current mode label shown as a badge (e.g. "LIVE", "PAUSED", "SEARCH").
	mode string
	// Badge style key: "green", "yellow", "red", "blue", "dim".
	modeStyle string

	width int
	theme theme.Theme
}

// New creates a Model.
func New(th theme.Theme) Model {
	return Model{theme: th, modeStyle: "green", mode: "LIVE"}
}

// SetKeyHints replaces the left key-hint text.
func (m *Model) SetKeyHints(s string) { m.keyHints = s }

// SetStats replaces the right stats text.
func (m *Model) SetStats(batches, events int) {
	m.stats = fmt.Sprintf(" batches:%d  events:%d ", batches, events)
}

// SetMode updates the mode badge.  style: "green"|"yellow"|"red"|"blue"|"dim".
func (m *Model) SetMode(label, style string) {
	m.mode = label
	m.modeStyle = style
}

// SetWidth updates the render width.
func (m *Model) SetWidth(w int) { m.width = w }

// SetTheme swaps the theme.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// View renders the status bar.
func (m Model) View() string {
	badge := m.renderBadge()
	left := "  " + m.keyHints
	right := m.stats

	badgeW := len([]rune(m.mode)) + 2
	gap := m.width - len(left) - len(right) - badgeW - 2
	if gap < 0 {
		gap = 0
	}
	content := left + strings.Repeat(" ", gap) + badge + right
	return m.theme.Footer.Width(m.width).Render(content)
}

func (m Model) renderBadge() string {
	switch m.modeStyle {
	case "green":
		return m.theme.BadgeGreen.Render(m.mode)
	case "yellow":
		return m.theme.BadgeYellow.Render(m.mode)
	case "red":
		return m.theme.BadgeRed.Render(m.mode)
	case "blue":
		return m.theme.BadgeBlue.Render(m.mode)
	default:
		return m.theme.BadgeDim.Render(m.mode)
	}
}
