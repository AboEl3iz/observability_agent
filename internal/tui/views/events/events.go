// Package events provides the Events tab view — a live, scrollable event stream
// with inline filtering and colour-coded event kinds.
package events

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/viewport"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/searchbar"
)

// View implements views.View for the Events tab.
type View struct {
	vp      viewport.Model
	events  []msg.Event
	search  searchbar.Model
	filter  string
	follow  bool
	theme   theme.Theme
	w, h    int
	dirty   bool
	cached  string
	focused bool
}

func New(th theme.Theme) *View {
	vp := viewport.New(80, 20)
	vp.SetContent("")
	return &View{
		vp:     vp,
		follow: true,
		theme:  th,
		search: searchbar.New(th),
	}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	v.events = append(v.events, batch.Events...)
	if len(v.events) > 2000 {
		v.events = v.events[len(v.events)-2000:]
	}
	v.dirty = true
	v.cached = ""
}

func (v *View) SetSize(w, h int) {
	v.w, v.h = w, h
	v.vp.Width = w
	searchH := 0
	if v.search.Visible() {
		searchH = 1
	}
	v.vp.Height = h - 2 - searchH
	v.dirty = true; v.cached = ""
}

func (v *View) SetTheme(th theme.Theme) { v.theme = th; v.search.SetTheme(th); v.dirty = true; v.cached = "" }
func (v *View) Focus()                  { v.focused = true }
func (v *View) Blur()                   { v.focused = false }
func (v *View) StatusLine() string {
	live := "LIVE"
	if !v.follow { live = "PAUSED" }
	return fmt.Sprintf("Events [%d]  %s  ·  G live  ·  / filter  ·  ↑↓ scroll", len(v.events), live)
}
func (v *View) SelectedContainer() string { return "" }

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	switch msg := tmsg.(type) {
	case tea.KeyMsg:
		if v.search.Visible() {
			switch msg.String() {
			case "esc":
				v.search.Hide(); v.search.Reset(); v.filter = ""
				v.dirty = true; return v, nil
			case "enter":
				v.search.Hide()
				v.dirty = true; return v, nil
			}
			var cmd tea.Cmd; v.search, cmd = v.search.Update(tmsg)
			v.filter = v.search.Value(); v.dirty = true; return v, cmd
		}
		switch msg.String() {
		case "/":
			v.search.Show(); v.dirty = true; return v, nil
		case "g":
			v.vp.GotoTop(); v.follow = false
		case "G":
			v.follow = true
		case "up", "k":
			v.follow = false; v.vp.LineUp(1)
		case "down", "j":
			v.vp.LineDown(1)
		case "pgup":
			v.follow = false; v.vp.HalfViewUp()
		case "pgdown":
			v.vp.HalfViewDown()
		}
		v.dirty = true
	}
	var cmd tea.Cmd
	v.vp, cmd = v.vp.Update(tmsg)
	return v, cmd
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" { return v.cached }

	// Rebuild viewport content.
	lines := v.buildLines()
	v.vp.SetContent(strings.Join(lines, "\n"))
	if v.follow {
		v.vp.GotoBottom()
	}

	title := v.theme.PanelTitle.Render(fmt.Sprintf("  ⚡ Real-time Events  [%d]", len(v.events)))
	var sb strings.Builder
	sb.WriteString(title + "\n")
	sb.WriteString(v.vp.View())
	if v.search.Visible() {
		sb.WriteString("\n" + v.search.View(v.w))
	}
	v.cached = sb.String(); v.dirty = false
	return v.cached
}

// ─── Internal ────────────────────────────────────────────────────────────────

func (v *View) buildLines() []string {
	var lines []string
	for _, ev := range v.events {
		if v.filter != "" &&
			!strings.Contains(strings.ToLower(ev.Message), strings.ToLower(v.filter)) &&
			!strings.Contains(strings.ToLower(ev.Container), strings.ToLower(v.filter)) {
			continue
		}
		ts := v.theme.TableDim.Render(ev.At.Format("15:04:05"))
		styled := v.styleEvent(ev)
		lines = append(lines, ts+" "+styled)
	}
	if len(lines) == 0 {
		lines = []string{v.theme.TableDim.Render("  No events yet…")}
	}
	return lines
}

func (v *View) styleEvent(ev msg.Event) string {
	switch ev.Kind {
	case msg.EventKindTCP:
		return v.theme.EventTCP.Render(ev.Message)
	case msg.EventKindError:
		return v.theme.EventError.Render(ev.Message)
	case msg.EventKindOOM:
		return v.theme.EventOOM.Render(ev.Message)
	case msg.EventKindSlowSys:
		return v.theme.EventSlowSys.Render(ev.Message)
	default:
		return v.theme.EventInfo.Render(ev.Message)
	}
}

// Silence unused time import if events are empty.
var _ = time.Now

var _ views.View = (*View)(nil)
