// Package searchbar wraps bubbles/textinput to provide an inline search/filter
// widget rendered at the bottom of the active view.
package searchbar

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"ebpf/internal/tui/theme"
)

// Model is the searchbar widget state.
type Model struct {
	input   textinput.Model
	visible bool
	theme   theme.Theme
}

// New creates a hidden searchbar.
func New(th theme.Theme) Model {
	ti := textinput.New()
	ti.Placeholder = "filter…"
	ti.CharLimit = 64
	return Model{input: ti, theme: th}
}

// Show opens the search bar and focuses the input.
func (m *Model) Show() {
	m.visible = true
	m.input.Focus()
}

// Hide closes the search bar.
func (m *Model) Hide() {
	m.visible = false
	m.input.Blur()
}

// Reset clears the input value.
func (m *Model) Reset() {
	m.input.Reset()
}

// Visible reports whether the searchbar is open.
func (m Model) Visible() bool { return m.visible }

// Value returns the current filter string.
func (m Model) Value() string { return m.input.Value() }

// SetTheme swaps the theme.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// Update delegates keyboard input to the underlying textinput.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.visible {
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// View renders the search bar as a single line.
func (m Model) View(width int) string {
	if !m.visible {
		return ""
	}
	prefix := m.theme.BadgeBlue.Render(" / ")
	input := m.theme.SearchBox.Width(width - 5).Render(m.input.View())
	return prefix + input
}
