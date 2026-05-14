// Package theme defines the Theme type and all builtin themes.
//
// # Design principle
//
// All lipgloss.Style values are constructed once at startup (in the theme
// constructors below) and stored as struct fields.  The render hot-path
// must never call lipgloss.NewStyle(); it only calls style.Render(s).
// This eliminates most per-frame allocations and prevents flicker.
package theme

import "github.com/charmbracelet/lipgloss"

// ─── Color palette (unexported) ───────────────────────────────────────────────

type palette struct {
	bgBase    lipgloss.Color
	bgSurface lipgloss.Color
	bgOverlay lipgloss.Color
	fg        lipgloss.Color
	fgDim     lipgloss.Color
	fgSubtle  lipgloss.Color
	green     lipgloss.Color
	red       lipgloss.Color
	yellow    lipgloss.Color
	blue      lipgloss.Color
	cyan      lipgloss.Color
	magenta   lipgloss.Color
	orange    lipgloss.Color
}

// ─── Theme ────────────────────────────────────────────────────────────────────

// Theme holds both raw colors and pre-built LipGloss styles for every
// reusable TUI component.  Always access styles via the struct fields rather
// than constructing new ones.
type Theme struct {
	Name string

	// Raw colors (used by widgets that need custom inline styling)
	BgBase    lipgloss.Color
	BgSurface lipgloss.Color
	BgOverlay lipgloss.Color
	Fg        lipgloss.Color
	FgDim     lipgloss.Color
	FgSubtle  lipgloss.Color
	Green     lipgloss.Color
	Red       lipgloss.Color
	Yellow    lipgloss.Color
	Blue      lipgloss.Color
	Cyan      lipgloss.Color
	Magenta   lipgloss.Color
	Orange    lipgloss.Color

	// Chrome styles
	Header    lipgloss.Style
	Footer    lipgloss.Style
	Separator lipgloss.Style

	// Tab bar
	TabActive   lipgloss.Style
	TabInactive lipgloss.Style
	TabBar      lipgloss.Style

	// Table
	TableHeader   lipgloss.Style
	TableRow      lipgloss.Style
	TableAltRow   lipgloss.Style
	TableSelected lipgloss.Style
	TableDim      lipgloss.Style

	// Borders / panels
	PanelBorder   lipgloss.Style
	PanelTitle    lipgloss.Style
	PanelFocused  lipgloss.Style

	// Overlays
	ModalBox   lipgloss.Style
	ModalTitle lipgloss.Style

	// Inputs
	SearchBox    lipgloss.Style
	PaletteBox   lipgloss.Style
	PaletteMatch lipgloss.Style

	// Badges / status
	BadgeGreen  lipgloss.Style
	BadgeRed    lipgloss.Style
	BadgeYellow lipgloss.Style
	BadgeBlue   lipgloss.Style
	BadgeDim    lipgloss.Style

	// Events
	EventInfo    lipgloss.Style
	EventTCP     lipgloss.Style
	EventError   lipgloss.Style
	EventOOM     lipgloss.Style
	EventSlowSys lipgloss.Style

	// Sparkline
	SparkBar lipgloss.Style
}

// build constructs a Theme from a palette, wiring all styles.
// Called once per theme at package init time.
func build(name string, p palette) Theme {
	t := Theme{
		Name:      name,
		BgBase:    p.bgBase,
		BgSurface: p.bgSurface,
		BgOverlay: p.bgOverlay,
		Fg:        p.fg,
		FgDim:     p.fgDim,
		FgSubtle:  p.fgSubtle,
		Green:     p.green,
		Red:       p.red,
		Yellow:    p.yellow,
		Blue:      p.blue,
		Cyan:      p.cyan,
		Magenta:   p.magenta,
		Orange:    p.orange,
	}

	base := lipgloss.NewStyle()

	// Chrome
	t.Header = base.Background(p.bgSurface).Foreground(p.fg).Bold(true).Padding(0, 1)
	t.Footer = base.Background(p.bgSurface).Foreground(p.fgDim).Padding(0, 1)
	t.Separator = base.Foreground(p.bgOverlay)

	// Tab bar
	t.TabBar = base.Background(p.bgBase)
	t.TabActive = base.Background(p.blue).Foreground(p.bgBase).Bold(true).Padding(0, 2)
	t.TabInactive = base.Background(p.bgSurface).Foreground(p.fgDim).Padding(0, 2)

	// Table
	t.TableHeader = base.Foreground(p.fgSubtle).Italic(true).Bold(false)
	t.TableRow = base.Foreground(p.fg)
	t.TableAltRow = base.Foreground(p.fg).Background(p.bgSurface)
	t.TableSelected = base.Background(p.blue).Foreground(p.bgBase).Bold(true)
	t.TableDim = base.Foreground(p.fgDim)

	// Panels
	t.PanelBorder = base.BorderStyle(lipgloss.RoundedBorder()).BorderForeground(p.bgOverlay)
	t.PanelTitle = base.Foreground(p.blue).Bold(true)
	t.PanelFocused = base.BorderStyle(lipgloss.RoundedBorder()).BorderForeground(p.blue)

	// Overlays
	t.ModalBox = base.Background(p.bgSurface).BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(p.blue).Padding(1, 2)
	t.ModalTitle = base.Foreground(p.blue).Bold(true)

	// Inputs
	t.SearchBox = base.Background(p.bgOverlay).Foreground(p.fg).Padding(0, 1)
	t.PaletteBox = base.Background(p.bgOverlay).Foreground(p.fg).Padding(0, 1)
	t.PaletteMatch = base.Foreground(p.yellow).Bold(true)

	// Badges
	t.BadgeGreen = base.Background(p.green).Foreground(p.bgBase).Bold(true).Padding(0, 1)
	t.BadgeRed = base.Background(p.red).Foreground(p.bgBase).Bold(true).Padding(0, 1)
	t.BadgeYellow = base.Background(p.yellow).Foreground(p.bgBase).Bold(true).Padding(0, 1)
	t.BadgeBlue = base.Background(p.blue).Foreground(p.bgBase).Bold(true).Padding(0, 1)
	t.BadgeDim = base.Background(p.bgOverlay).Foreground(p.fgDim).Padding(0, 1)

	// Events
	t.EventInfo = base.Foreground(p.blue)
	t.EventTCP = base.Foreground(p.green)
	t.EventError = base.Foreground(p.red)
	t.EventOOM = base.Foreground(p.red).Bold(true)
	t.EventSlowSys = base.Foreground(p.yellow)

	// Sparkline
	t.SparkBar = base.Foreground(p.cyan)

	return t
}

// Get returns the named builtin theme, falling back to GithubDark if unknown.
func Get(name string) Theme {
	if t, ok := builtins[name]; ok {
		return t
	}
	return builtins["github-dark"]
}

// Names returns all builtin theme names in a stable order.
func Names() []string {
	return []string{"github-dark", "nord", "gruvbox", "tokyo-night", "catppuccin", "solarized"}
}
