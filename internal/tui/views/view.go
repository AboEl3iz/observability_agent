// Package views defines the View interface that every tab view must implement.
// The App root model delegates lifecycle calls to the active View only,
// keeping non-visible views from consuming CPU.
package views

import (
	tea "github.com/charmbracelet/bubbletea"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
)

// View is the contract every tab view must satisfy.
type View interface {
	// Init returns any startup commands (e.g. subscriptions).
	Init() tea.Cmd

	// SetData is called on every DataMsg with the latest snapshot.
	// Implementations should update internal state and set dirty=true.
	SetData(batch msg.DataBatch)

	// SetSize informs the view of its available render dimensions.
	SetSize(width, height int)

	// SetTheme propagates a theme change to the view and its children.
	SetTheme(th theme.Theme)

	// Update handles the BubbleTea message for this view.
	// It is called only when the view is the active tab.
	Update(msg tea.Msg) (View, tea.Cmd)

	// View renders the view content for the current (width, height).
	View() string

	// Focus / Blur are called when the user navigates to/from this view.
	Focus()
	Blur()

	// StatusLine returns a short string for the status bar while active.
	StatusLine() string

	// SelectedContainer returns the container name of the highlighted table row,
	// or "" if nothing is selected (used to open the detail page).
	SelectedContainer() string
}
