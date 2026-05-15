// Package app — root BubbleTea model.
//
// App is the single root model handed to tea.NewProgram.  It owns:
//   - The application state machine (AppState)
//   - The tab bar and active view slot
//   - All overlay widgets (modal, command palette)
//   - The layout engine
//   - The dual-tick cycle (render + data)
package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/config"
	"ebpf/internal/tui/layout"
	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/modal"
	"ebpf/internal/tui/widgets/palette"
	"ebpf/internal/tui/widgets/statusbar"
	"ebpf/internal/tui/widgets/tabbar"

	cpuView "ebpf/internal/tui/views/cpu"
	detailView "ebpf/internal/tui/views/detail"
	eventsView "ebpf/internal/tui/views/events"
	graphsView "ebpf/internal/tui/views/graphs"
	ioView "ebpf/internal/tui/views/io"
	memView "ebpf/internal/tui/views/memory"
	netView "ebpf/internal/tui/views/network"
	overView "ebpf/internal/tui/views/overview"
	sysView "ebpf/internal/tui/views/syscall"
)

// Tab indices.
const (
	tabOverview = 0
	tabCPU      = 1
	tabMemory   = 2
	tabIO       = 3
	tabNetwork  = 4
	tabSyscall  = 5
	tabEvents   = 6
	tabGraphs   = 7
)

// App is the root BubbleTea model.
type App struct {
	state     AppState
	prevState AppState

	// Layout
	layout layout.Layout

	// Theme
	theme     theme.Theme
	themeIdx  int

	// Chrome widgets
	tabs      tabbar.Model
	statusBar statusbar.Model

	// Overlays
	modal   modal.Model
	palette palette.Model

	// Tab views (indices match tab* constants above)
	tabViews  []views.View
	detailPg  *detailView.View

	// Config + collectors
	cfg     config.Config
	colls   *CollectorSet
	demo    bool

	// Render dimensions
	termW, termH int

	// Batch counter for status bar
	batchCount int
	eventCount int
}

// New constructs the App.
func New(cfg config.Config, colls *CollectorSet, demo bool) *App {
	th := theme.Get(cfg.Theme)

	tabs := tabbar.New([]tabbar.Tab{
		{Title: "Overview", Key: "1"},
		{Title: "CPU", Key: "2"},
		{Title: "Memory", Key: "3"},
		{Title: "I/O", Key: "4"},
		{Title: "Network", Key: "5"},
		{Title: "Syscall", Key: "6"},
		{Title: "Events", Key: "7"},
		{Title: "Graphs", Key: "8"},
	}, th)

	tabViews := []views.View{
		overView.New(th),
		cpuView.New(th),
		memView.New(th),
		ioView.New(th),
		netView.New(th),
		sysView.New(th),
		eventsView.New(th),
		graphsView.New(th),
	}
	tabViews[tabOverview].Focus()

	detail := detailView.New(th)

	cmds := buildCommands(cfg)
	pal := palette.New(cmds, th)

	themeIdx := 0
	for i, n := range theme.Names() {
		if n == cfg.Theme {
			themeIdx = i
			break
		}
	}

	return &App{
		state:     StateLoading,
		theme:     th,
		themeIdx:  themeIdx,
		layout:    layout.New(80, 24),
		tabs:      tabs,
		statusBar: statusbar.New(th),
		modal:     modal.New(th),
		palette:   pal,
		tabViews:  tabViews,
		detailPg:  detail,
		cfg:       cfg,
		colls:     colls,
		demo:      demo,
	}
}

// ─── Init ─────────────────────────────────────────────────────────────────────

func (a App) Init() tea.Cmd {
	return tea.Batch(
		RenderTickCmd(a.cfg.RenderInterval()),
		CollectCmd(0, a.colls, a.demo, a.collectFilter()),
	)
}

// ContainersOnly and TopN satisfy the old interface — kept for compatibility.
func (a App) ContainersOnly() bool { return a.cfg.ContainersOnly }
func (a App) TopN() int            { return a.cfg.TopN }

// collectFilter snapshots the current config as a CollectFilter value.
// This is passed into the collector goroutine so it is goroutine-safe.
func (a App) collectFilter() CollectFilter {
	return CollectFilter{
		ContainersOnly: a.cfg.ContainersOnly,
		TopN:           a.cfg.TopN,
		ShowFiles:      a.cfg.ShowFiles,
		ShowTCP:        a.cfg.ShowTCP,
		ShowSlowSys:    a.cfg.ShowSlowSys,
	}
}

// ─── Update ───────────────────────────────────────────────────────────────────

func (a App) Update(teaMsg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := teaMsg.(type) {

	// ── Window resize ────────────────────────────────────────────────────────
	case tea.WindowSizeMsg:
		a.termW, a.termH = m.Width, m.Height
		a.layout = layout.New(m.Width, m.Height)
		a.tabs.SetWidth(m.Width)
		a.statusBar.SetWidth(m.Width)
		for _, v := range a.tabViews {
			v.SetSize(a.layout.ContentW(), a.layout.BodyH())
		}
		a.detailPg.SetSize(a.layout.ContentW(), a.layout.BodyH())
		return a, nil

	// ── Render tick ──────────────────────────────────────────────────────────
	case msg.RenderTickMsg:
		return a, RenderTickCmd(a.cfg.RenderInterval())

	// ── Data message ─────────────────────────────────────────────────────────
	case msg.DataMsg:
		if a.state == StateLoading {
			a.state = StateDashboard
		}
		a.batchCount++
		a.eventCount += len(m.Batch.Events)
		// Propagate to all tab views (they cache internally).
		for _, v := range a.tabViews {
			v.SetData(m.Batch)
		}
		a.detailPg.SetData(m.Batch)
		a.statusBar.SetStats(a.batchCount, a.eventCount)
		// Re-issue data collection.
		return a, CollectCmd(a.cfg.DataInterval(), a.colls, a.demo, a.collectFilter())

	// ── Navigation messages ───────────────────────────────────────────────────
	case msg.NavDetailMsg:
		a.detailPg.SetContainer(m.Container)
		a.prevState = a.state
		a.state = StateDetail
		a.statusBar.SetMode("DETAIL", "blue")
		return a, nil

	case msg.NavBackMsg:
		a.state = a.prevState
		if a.state == StateDetail {
			a.state = StateDashboard
		}
		a.statusBar.SetMode("LIVE", "green")
		return a, nil

	case msg.ThemeChangedMsg:
		return a.applyTheme(m.Name), nil

	// ── Keyboard input ────────────────────────────────────────────────────────
	case tea.KeyMsg:
		return a.handleKey(m)
	}

	// Delegate to palette / modal if open.
	if a.palette.Visible() {
		var cmd tea.Cmd
		a.palette, cmd = a.palette.Update(teaMsg)
		return a, cmd
	}

	// Delegate to active view.
	if a.state == StateDetail {
		newV, cmd := a.detailPg.Update(teaMsg)
		a.detailPg = newV.(*detailView.View)
		return a, cmd
	}
	newV, cmd := a.activeView().Update(teaMsg)
	a.tabViews[a.tabs.Active()] = newV
	return a, cmd
}

// handleKey processes keyboard events through the global → overlay → view chain.
func (a App) handleKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()

	// Palette absorbs all input when open.
	if a.palette.Visible() {
		var cmd tea.Cmd
		a.palette, cmd = a.palette.Update(m)
		return a, cmd
	}

	// Help modal: any key closes it.
	if a.modal.Visible() {
		a.modal.Hide()
		a.state = a.prevState
		return a, nil
	}

	// Global bindings (always active).
	switch key {
	case "q", "ctrl+c":
		return a, tea.Quit
	case "?":
		a.prevState = a.state
		a.state = StateHelp
		a.modal.ShowHelp(helpContent())
		return a, nil
	case ":":
		a.state = StateCommandPalette
		a.palette.Show()
		return a, nil
	case "esc":
		if a.state == StateDetail || a.state == StateSearch {
			a.state = StateDashboard
			a.statusBar.SetMode("LIVE", "green")
		}
		return a, nil
	case "T":
		// Cycle themes.
		names := theme.Names()
		a.themeIdx = (a.themeIdx + 1) % len(names)
		return a.applyTheme(names[a.themeIdx]), nil
	case "tab", "]":
		a.tabs.Next()
		a.blurAll()
		a.activeView().Focus()
		return a, nil
	case "shift+tab", "[":
		a.tabs.Prev()
		a.blurAll()
		a.activeView().Focus()
		return a, nil
	case "1", "2", "3", "4", "5", "6", "7", "8":
		idx := int(key[0]-'1')
		if idx < len(a.tabViews) {
			a.blurAll()
			a.tabs.SetActive(idx)
			a.activeView().Focus()
		}
		return a, nil
	case "enter":
		// Open detail page for selected row.
		if a.state == StateDashboard {
			container := a.activeView().SelectedContainer()
			if container != "" {
				return a.Update(msg.NavDetailMsg{Container: container})
			}
		}
	}

	// Delegate to active view.
	if a.state == StateDetail {
		newV, cmd := a.detailPg.Update(m)
		a.detailPg = newV.(*detailView.View)
		return a, cmd
	}
	newV, cmd := a.activeView().Update(m)
	a.tabViews[a.tabs.Active()] = newV
	return a, cmd
}

// ─── View ─────────────────────────────────────────────────────────────────────

func (a App) View() string {
	if a.termW == 0 {
		return "Initialising…"
	}

	// Always render the chrome layers.
	header := a.renderHeader()
	tabBar := a.tabs.View()
	statusLine := a.renderStatusBar()

	// Content area.
	var content string
	switch a.state {
	case StateLoading:
		content = a.renderLoading()
	case StateDetail:
		content = a.detailPg.View()
	default:
		content = a.activeView().View()
	}

	full := lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabBar,
		content,
		statusLine,
	)

	// Overlay layers.
	if a.modal.Visible() {
		return a.modal.Render(full, a.termW, a.termH)
	}
	if a.palette.Visible() {
		overlay := a.palette.View(a.termW, a.termH)
		return lipgloss.Place(a.termW, a.termH, lipgloss.Center, lipgloss.Center, overlay)
	}

	return full
}

// ─── Header ───────────────────────────────────────────────────────────────────

func (a App) renderHeader() string {
	now := time.Now().Format("2006-01-02  15:04:05")
	mode := "LIVE"
	if a.demo {
		mode = "DEMO"
	}
	modeStyle := a.theme.BadgeGreen
	if a.demo {
		modeStyle = a.theme.BadgeYellow
	}
	badge := modeStyle.Render(" " + mode + " ")
	ts := a.theme.Header.Copy().Foreground(a.theme.FgDim).Render("  " + now)
	left := "  ◉ eBPF Observer  [" + a.theme.Name + "]"
	gap := a.termW - len([]rune(left)) - lipgloss.Width(badge) - lipgloss.Width(ts) - 4
	if gap < 0 {
		gap = 0
	}
	return a.theme.Header.Width(a.termW).Render(
		left + strings.Repeat(" ", gap) + badge + ts,
	)
}

func (a App) renderStatusBar() string {
	if a.state == StateDetail {
		a.statusBar.SetKeyHints(a.detailPg.StatusLine())
	} else {
		a.statusBar.SetKeyHints(a.activeView().StatusLine() + "  ·  T theme  ·  ? help  ·  q quit")
	}
	return a.statusBar.View()
}

func (a App) renderLoading() string {
	lines := a.layout.BodyH()
	half := lines / 2
	var sb strings.Builder
	for i := 0; i < half; i++ {
		sb.WriteString(strings.Repeat(" ", a.termW) + "\n")
	}
	spinner := a.theme.BadgeBlue.Render("  ◌  Waiting for first eBPF snapshot…  ")
	sb.WriteString(lipgloss.NewStyle().Width(a.termW).Align(lipgloss.Center).Render(spinner))
	return sb.String()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (a App) activeView() views.View {
	return a.tabViews[a.tabs.Active()]
}

func (a *App) blurAll() {
	for _, v := range a.tabViews {
		v.Blur()
	}
}

func (a App) applyTheme(name string) App {
	th := theme.Get(name)
	a.theme = th
	a.cfg.Theme = name
	a.tabs.SetTheme(th)
	a.statusBar.SetTheme(th)
	a.modal.SetTheme(th)
	a.palette.SetTheme(th)
	for _, v := range a.tabViews {
		v.SetTheme(th)
	}
	a.detailPg.SetTheme(th)
	// Persist asynchronously (best-effort).
	go func() { _ = config.Save(a.cfg) }()
	return a
}

func buildCommands(cfg config.Config) []palette.Command {
	cmds := []palette.Command{
		{Name: "quit", Description: "Exit the application"},
	}
	for _, n := range theme.Names() {
		name := n // capture
		cmds = append(cmds, palette.Command{
			Name:        "theme " + name,
			Description: "Switch to " + name + " theme",
			Action: func(_ string) tea.Cmd {
				return func() tea.Msg { return msg.ThemeChangedMsg{Name: name} }
			},
		})
	}
	return cmds
}

func helpContent() string {
	return `  Navigation
  ──────────
  Tab / ]       next tab
  Shift+Tab / [ prev tab
  1-8           jump to tab
  Enter         open container detail
  Esc           go back

  Table
  ─────
  ↑/k  ↓/j     move cursor
  PgUp/PgDn     page up/down
  g / G         top / live mode
  s / S         sort column next/prev
  /             filter mode
  y             yank row

  Detail page
  ───────────
  p             pause/resume
  /             filter events
  ↑↓ g G       scroll

  Global
  ──────
  T             cycle theme
  :             command palette
  ?             this help
  q / Ctrl+C    quit`
}

var _ tea.Model = App{}
var _ fmt.Stringer = AppState(0)
