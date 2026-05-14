// Package app defines the application state machine.
package app

// AppState enumerates every major mode the TUI can be in.
// Transitions are always explicit — no implicit state mutations.
type AppState int

const (
	// StateLoading shows a spinner while waiting for the first data batch.
	StateLoading AppState = iota

	// StateDashboard is the normal navigation mode (tab bar + active view).
	StateDashboard

	// StateDetail shows the single-container observability cockpit.
	StateDetail

	// StateSearch is active while the user is typing a filter query.
	// The search bar is rendered at the bottom of the active view.
	StateSearch

	// StateCommandPalette shows the command palette overlay.
	StateCommandPalette

	// StateHelp shows the help modal overlay.
	StateHelp
)

// String returns a human-readable name for logging.
func (s AppState) String() string {
	switch s {
	case StateLoading:
		return "Loading"
	case StateDashboard:
		return "Dashboard"
	case StateDetail:
		return "Detail"
	case StateSearch:
		return "Search"
	case StateCommandPalette:
		return "CommandPalette"
	case StateHelp:
		return "Help"
	default:
		return "Unknown"
	}
}
