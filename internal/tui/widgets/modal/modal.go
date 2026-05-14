// Package modal provides a centred overlay widget for help, error messages,
// and confirmation dialogs.  It renders over the existing content using
// lipgloss.Place so the background is not erased.
package modal

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/theme"
)

// Kind classifies the modal for icon/color selection.
type Kind int

const (
	KindHelp    Kind = iota // ? help overlay
	KindError               // error message
	KindConfirm             // yes/no prompt
)

// Model is the modal widget state.
type Model struct {
	kind    Kind
	title   string
	content string
	visible bool
	theme   theme.Theme
}

// New creates a hidden modal.
func New(th theme.Theme) Model { return Model{theme: th} }

// ShowHelp populates and shows a help overlay.
func (m *Model) ShowHelp(content string) {
	m.kind = KindHelp
	m.title = "  Keyboard Shortcuts"
	m.content = content
	m.visible = true
}

// ShowError shows an error message.
func (m *Model) ShowError(msg string) {
	m.kind = KindError
	m.title = "  Error"
	m.content = msg
	m.visible = true
}

// Hide hides the modal.
func (m *Model) Hide() { m.visible = false }

// Visible reports whether the modal is shown.
func (m Model) Visible() bool { return m.visible }

// SetTheme swaps the theme.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// Render draws the modal centred over background, returning the combined string.
func (m Model) Render(background string, termW, termH int) string {
	if !m.visible {
		return background
	}

	icon := "?"
	switch m.kind {
	case KindError:
		icon = "✗"
	case KindConfirm:
		icon = "!"
	}
	_ = icon

	lines := strings.Split(m.content, "\n")
	maxW := 0
	for _, l := range lines {
		if len([]rune(l)) > maxW {
			maxW = len([]rune(l))
		}
	}
	boxW := maxW + 6
	if boxW < 40 {
		boxW = 40
	}
	if boxW > termW-4 {
		boxW = termW - 4
	}

	title := m.theme.ModalTitle.Render(m.title)
	body := strings.Join(lines, "\n")
	box := m.theme.ModalBox.Width(boxW).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, "", body),
	)

	return lipgloss.Place(termW, termH,
		lipgloss.Center, lipgloss.Center,
		box,
		lipgloss.WithWhitespaceBackground(lipgloss.Color(m.theme.BgBase)),
	)
}
