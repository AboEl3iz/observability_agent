// Package keys centralises all keyboard bindings used by the TUI.
// Using typed key.Binding values (from charmbracelet/bubbles/key) means
// every binding is self-documenting and the help overlay is generated
// automatically.
package keys

import "github.com/charmbracelet/bubbles/key"

// ─── Global key map (always active) ──────────────────────────────────────────

// GlobalKeyMap contains bindings that are processed before any view-local
// bindings.  If a key matches here it is consumed and not forwarded.
type GlobalKeyMap struct {
	Quit           key.Binding
	Help           key.Binding
	CommandPalette key.Binding
	NextTab        key.Binding
	PrevTab        key.Binding
	ThemeCycle     key.Binding
	Back           key.Binding
}

// Global is the singleton global key map.
var Global = GlobalKeyMap{
	Quit:           key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Help:           key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	CommandPalette: key.NewBinding(key.WithKeys(":"), key.WithHelp(":", "command palette")),
	NextTab:        key.NewBinding(key.WithKeys("tab", "]"), key.WithHelp("tab/]", "next tab")),
	PrevTab:        key.NewBinding(key.WithKeys("shift+tab", "["), key.WithHelp("[", "prev tab")),
	ThemeCycle:     key.NewBinding(key.WithKeys("T"), key.WithHelp("T", "cycle theme")),
	Back:           key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
}

// ─── Table key map ────────────────────────────────────────────────────────────

// TableKeyMap contains bindings that are active when a VirtualTable has focus.
type TableKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding
	Select   key.Binding
	Search   key.Binding
	SortNext key.Binding
	SortPrev key.Binding
	CopyRow  key.Binding
}

// Table is the singleton table key map.
var Table = TableKeyMap{
	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	PageUp:   key.NewBinding(key.WithKeys("pgup", "ctrl+u"), key.WithHelp("pgup", "page up")),
	PageDown: key.NewBinding(key.WithKeys("pgdown", "ctrl+d"), key.WithHelp("pgdn", "page down")),
	Top:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
	Bottom:   key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
	Select:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "detail")),
	Search:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
	SortNext: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort ▼")),
	SortPrev: key.NewBinding(key.WithKeys("S"), key.WithHelp("S", "sort ▲")),
	CopyRow:  key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "yank row")),
}

// ─── Viewport / events key map ────────────────────────────────────────────────

// ViewportKeyMap is used by the events view and the detail page viewport.
type ViewportKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding
}

// Viewport is the singleton viewport key map.
var Viewport = ViewportKeyMap{
	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "scroll up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "scroll down")),
	PageUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
	PageDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
	Top:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
	Bottom:   key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "live/bottom")),
}

// ShortHelp returns a compact slice of bindings for the footer status bar.
func ShortHelp() []key.Binding {
	return []key.Binding{
		Global.NextTab, Global.Back, Table.Select, Table.Search,
		Table.SortNext, Global.CommandPalette, Global.Help, Global.Quit,
	}
}
