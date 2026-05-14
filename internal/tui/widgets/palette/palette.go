// Package palette provides the command palette widget — a `:command` style
// popup with fuzzy matching, inspired by k9s and VS Code.
package palette

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/theme"
)

// Command is a single registered command.
type Command struct {
	Name        string // e.g. "theme"
	Args        string // argument placeholder, e.g. "<name>"
	Description string
	Action      func(args string) tea.Cmd
}

// Model is the command palette widget state.
type Model struct {
	commands []Command
	matches  []Command
	input    textinput.Model
	cursor   int
	visible  bool
	theme    theme.Theme
}

// New creates a hidden command palette with the given commands.
func New(commands []Command, th theme.Theme) Model {
	ti := textinput.New()
	ti.Placeholder = "type a command…"
	ti.CharLimit = 128
	return Model{commands: commands, input: ti, theme: th}
}

// Show opens the palette.
func (m *Model) Show() {
	m.visible = true
	m.cursor = 0
	m.input.Focus()
	m.filter("")
}

// Hide closes the palette.
func (m *Model) Hide() {
	m.visible = false
	m.input.Blur()
	m.input.Reset()
	m.matches = nil
}

// Visible reports whether the palette is open.
func (m Model) Visible() bool { return m.visible }

// SetTheme swaps the theme.
func (m *Model) SetTheme(th theme.Theme) { m.theme = th }

// AddCommand registers a new command at runtime.
func (m *Model) AddCommand(c Command) { m.commands = append(m.commands, c) }

// Update handles keyboard input.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.visible {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.Hide()
			return m, nil
		case "enter":
			if len(m.matches) > 0 {
				cmd := m.matches[m.cursor]
				val := strings.TrimSpace(m.input.Value())
				// Strip command name, pass remaining as args.
				args := strings.TrimPrefix(val, cmd.Name)
				args = strings.TrimSpace(args)
				m.Hide()
				if cmd.Action != nil {
					return m, cmd.Action(args)
				}
			}
			return m, nil
		case "up", "ctrl+p":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "ctrl+n":
			if m.cursor < len(m.matches)-1 {
				m.cursor++
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.filter(m.input.Value())
	return m, cmd
}

// View renders the palette centred over the terminal.
func (m Model) View(termW, termH int) string {
	if !m.visible {
		return ""
	}
	boxW := min(termW-8, 70)

	var sb strings.Builder
	sb.WriteString(m.theme.ModalTitle.Render("  Command Palette"))
	sb.WriteString("\n\n")

	inputLine := m.theme.PaletteBox.Width(boxW - 4).Render(": " + m.input.View())
	sb.WriteString(inputLine)
	sb.WriteString("\n\n")

	maxItems := 8
	for i, c := range m.matches {
		if i >= maxItems {
			break
		}
		name := highlightMatch(c.Name+" "+c.Args, m.input.Value(), m.theme)
		desc := m.theme.TableDim.Render("  " + c.Description)
		line := lipgloss.JoinHorizontal(lipgloss.Top,
			name, desc,
		)
		if i == m.cursor {
			sb.WriteString(m.theme.TableSelected.Width(boxW-4).Render(line))
		} else {
			sb.WriteString(m.theme.TableRow.Width(boxW-4).Render(line))
		}
		sb.WriteByte('\n')
	}

	box := m.theme.ModalBox.Width(boxW).Render(sb.String())
	return lipgloss.Place(termW, termH,
		lipgloss.Center, lipgloss.Center,
		box,
	)
}

// ─── Internal ────────────────────────────────────────────────────────────────

func (m *Model) filter(q string) {
	q = strings.TrimSpace(strings.ToLower(q))
	m.matches = m.matches[:0]
	for _, c := range m.commands {
		if q == "" || strings.Contains(strings.ToLower(c.Name), q) ||
			strings.Contains(strings.ToLower(c.Description), q) {
			m.matches = append(m.matches, c)
		}
	}
	if m.cursor >= len(m.matches) {
		m.cursor = max(0, len(m.matches)-1)
	}
}

// highlightMatch bolds the matching prefix of name.
func highlightMatch(name, q string, th theme.Theme) string {
	if q == "" {
		return th.TableRow.Render("  " + name)
	}
	lo := strings.ToLower(name)
	idx := strings.Index(lo, strings.ToLower(q))
	if idx < 0 {
		return th.TableRow.Render("  " + name)
	}
	return "  " + name[:idx] +
		th.PaletteMatch.Render(name[idx:idx+len(q)]) +
		name[idx+len(q):]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
