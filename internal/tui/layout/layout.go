// Package layout computes the pixel-perfect region dimensions for every chrome
// element of the TUI, given the current terminal size.  All View and widget
// code should query Layout rather than doing ad-hoc arithmetic.
package layout

// Layout holds the current terminal dimensions and derived region sizes.
type Layout struct {
	TermW int
	TermH int

	// Optional side panel (detail cockpit sub-panels, future sidebar)
	HasSidebar bool
	SidebarW   int // default 30
}

// New returns a Layout for the given terminal size.
func New(w, h int) Layout {
	return Layout{TermW: w, TermH: h, SidebarW: 30}
}

// ── Chrome heights ─────────────────────────────────────────────────────────

func (l Layout) HeaderH() int    { return 1 }
func (l Layout) TabBarH() int    { return 1 }
func (l Layout) StatusBarH() int { return 1 }
func (l Layout) FooterH() int    { return 1 }

// ChromeH is the total height consumed by non-content chrome.
func (l Layout) ChromeH() int {
	return l.HeaderH() + l.TabBarH() + l.StatusBarH() + l.FooterH()
}

// ── Content area ──────────────────────────────────────────────────────────

// BodyH is the usable content height (terminal minus all chrome rows).
func (l Layout) BodyH() int {
	h := l.TermH - l.ChromeH()
	if h < 4 {
		h = 4
	}
	return h
}

// ContentW is the usable width for the main content area.
func (l Layout) ContentW() int {
	w := l.TermW
	if l.HasSidebar {
		w -= l.SidebarW + 1 // +1 for the divider
	}
	if w < 20 {
		w = 20
	}
	return w
}

// ── Region helpers ────────────────────────────────────────────────────────

// ContentRegion returns the (x, y, width, height) of the main content area.
func (l Layout) ContentRegion() (x, y, w, h int) {
	return 0, l.HeaderH() + l.TabBarH(), l.ContentW(), l.BodyH()
}

// SidebarRegion returns the (x, y, width, height) of the optional sidebar.
// Only meaningful when HasSidebar is true.
func (l Layout) SidebarRegion() (x, y, w, h int) {
	return l.ContentW() + 1, l.HeaderH() + l.TabBarH(), l.SidebarW, l.BodyH()
}

// SplitVertical splits the body height into top/bottom proportions.
// ratio is the fraction assigned to the top pane (0.0–1.0).
func (l Layout) SplitVertical(ratio float64) (topH, botH int) {
	topH = int(float64(l.BodyH()) * ratio)
	botH = l.BodyH() - topH
	if topH < 3 {
		topH = 3
	}
	if botH < 3 {
		botH = 3
	}
	return
}

// SplitHorizontal splits the content width into left/right proportions.
func (l Layout) SplitHorizontal(ratio float64) (leftW, rightW int) {
	leftW = int(float64(l.ContentW()) * ratio)
	rightW = l.ContentW() - leftW
	if leftW < 10 {
		leftW = 10
	}
	if rightW < 10 {
		rightW = 10
	}
	return
}
