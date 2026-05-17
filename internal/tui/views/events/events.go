// Package events provides the Events tab view — a live, scrollable event stream
// with inline filtering and colour-coded event kinds.
package events

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/internal/tui/widgets/searchbar"
	"ebpf/pkg/event"
)

// View implements views.View for the Events tab.
type View struct {
	vp      viewport.Model
	events  []msg.Event
	search  searchbar.Model
	filter  string
	follow  bool
	theme   theme.Theme
	styles  eventStyles
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
		styles: buildEventStyles(th),
		search: searchbar.New(th),
	}
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) SetData(batch msg.DataBatch) {
	for _, newEv := range batch.Events {
		if newEv.Count == 0 {
			newEv.Count = 1
		}

		merged := false
		// Scan backwards through recent events (up to 5 seconds) to merge duplicates
		for i := len(v.events) - 1; i >= 0; i-- {
			oldEv := &v.events[i]
			// Stop scanning if we go back more than 5 seconds to prevent over-merging
			if newEv.At.Sub(oldEv.At) > 5*time.Second {
				break
			}

			// Merge if exact same kind, container, and message content
			if oldEv.Kind == newEv.Kind && oldEv.Container == newEv.Container && oldEv.Message == newEv.Message {
				oldEv.Count += newEv.Count
				oldEv.At = newEv.At // Update to latest occurrence timestamp
				merged = true
				break
			}
		}

		if !merged {
			v.events = append(v.events, newEv)
		}
	}

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

func (v *View) SetTheme(th theme.Theme) { 
	v.theme = th
	v.styles = buildEventStyles(th)
	v.search.SetTheme(th)
	v.dirty = true
	v.cached = ""
}
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
		if ev.Count > 1 {
			styled += v.theme.TableDim.Render(fmt.Sprintf(" (x%d)", ev.Count))
		}
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
		if ev.Envelope != nil {
			return v.formatSecurityEvent(ev.Envelope)
		}
		return v.theme.EventOOM.Render(ev.Message)
	case msg.EventKindSlowSys:
		return v.theme.EventSlowSys.Render(ev.Message)
	case msg.EventKindSecurity:
		if ev.Envelope != nil {
			return v.formatSecurityEvent(ev.Envelope)
		}
		return v.theme.BadgeRed.Render(" SEC ") + " " + ev.Message
	default:
		return v.theme.EventInfo.Render(ev.Message)
	}
}

func (v *View) formatSecurityEvent(env *event.EventEnvelope) string {
	var b strings.Builder

	// 1. Badge based on EventType
	badge := ""
	switch env.EventType {
	case event.EventTypeExec:
		badge = v.styles.badgeExec.Render(" EXEC ")
	case event.EventTypeDNSQuery:
		badge = v.styles.badgeDNS.Render(" DNS  ")
	case event.EventTypePrivEsc:
		badge = v.styles.badgePriv.Render(" PRIV ")
	case event.EventTypeEscapeIndicator:
		badge = v.styles.badgeEscape.Render(" ESCP ")
	case event.EventTypeFork:
		badge = v.theme.BadgeDim.Render(" FORK ")
	case "oom_kill":
		badge = v.styles.badgeOOM.Render(" OOM  ")
	default:
		badge = v.theme.BadgeDim.Render(" SEC  ")
	}

	b.WriteString(badge)
	b.WriteString(" ")

	// 2. Container
	b.WriteString(v.styles.container.Render(fmt.Sprintf("[%s]", env.ContainerName)))
	b.WriteString(" ")

	// 3. Process Context
	procContext := env.Process
	if env.ParentProcess != "" {
		procContext = env.ParentProcess + " → " + env.Process
	}
	procContext += fmt.Sprintf(" (pid:%d)", env.PID)
	b.WriteString(v.styles.process.Render(procContext))

	// 4. Metadata
	if len(env.Metadata) > 0 {
		b.WriteString("  ")
		switch env.EventType {
		case event.EventTypeExec:
			if argv, ok := env.Metadata["argv"]; ok {
				b.WriteString(v.styles.metaExec.Render(fmt.Sprintf("cmd: %v", argv)))
			}
		case event.EventTypeDNSQuery:
			q := env.Metadata["query"]
			qt := env.Metadata["query_type"]
			b.WriteString(v.styles.metaDNS.Render(fmt.Sprintf("q: %v (%v)", q, qt)))
		case event.EventTypePrivEsc:
			op := env.Metadata["escalation_type"]
			
			// Try to find the most relevant target based on the escalation type
			var tgt any
			if pid, ok := env.Metadata["target_pid"]; ok {
				tgt = fmt.Sprintf("pid:%v", pid)
			} else if capName, ok := env.Metadata["capability"]; ok {
				tgt = capName
			} else if uid, ok := env.Metadata["new_uid"]; ok {
				tgt = fmt.Sprintf("uid:%v", uid)
			} else if gid, ok := env.Metadata["new_gid"]; ok {
				tgt = fmt.Sprintf("gid:%v", gid)
			} else {
				tgt = "<none>"
			}
			
			b.WriteString(v.styles.metaAlert.Render(fmt.Sprintf("op: %v tgt: %v", op, tgt)))
		case event.EventTypeEscapeIndicator:
			op := env.Metadata["indicator_type"]
			flags := env.Metadata["namespace_flags"]
			if flags == "" || flags == nil {
				flags = "<none>"
			}
			b.WriteString(v.styles.metaAlert.Render(fmt.Sprintf("op: %v flags: %v", op, flags)))
		case "oom_kill":
			rss := env.Metadata["rss_kb"]
			limitMB := int64(0)
			if lim, ok := env.Metadata["limit_bytes"].(uint64); ok {
				limitMB = int64(lim / (1024 * 1024))
			} else if lim, ok := env.Metadata["limit_bytes"].(float64); ok {
				limitMB = int64(lim / (1024 * 1024))
			} else if lim, ok := env.Metadata["limit_bytes"].(int64); ok {
				limitMB = lim / (1024 * 1024)
			}
			b.WriteString(v.styles.metaAlert.Render(fmt.Sprintf("rss: %vKB limit: %dMB", rss, limitMB)))
		default:
			// Just stringify if unhandled
			b.WriteString(v.theme.TableDim.Render(fmt.Sprintf("%v", env.Metadata)))
		}
	}

	return b.String()
}

// ─── Local Styles ─────────────────────────────────────────────────────────────

type eventStyles struct {
	badgeExec   lipgloss.Style
	badgeDNS    lipgloss.Style
	badgePriv   lipgloss.Style
	badgeEscape lipgloss.Style
	badgeOOM    lipgloss.Style
	container   lipgloss.Style
	process     lipgloss.Style
	metaExec    lipgloss.Style
	metaDNS     lipgloss.Style
	metaAlert   lipgloss.Style
}

func buildEventStyles(th theme.Theme) eventStyles {
	base := lipgloss.NewStyle()
	return eventStyles{
		badgeExec:   base.Background(th.Blue).Foreground(th.BgBase).Bold(true).Padding(0, 1),
		badgeDNS:    base.Background(th.Green).Foreground(th.BgBase).Bold(true).Padding(0, 1),
		badgePriv:   base.Background(th.Orange).Foreground(th.BgBase).Bold(true).Padding(0, 1),
		badgeEscape: base.Background(th.Red).Foreground(th.BgBase).Bold(true).Padding(0, 1),
		badgeOOM:    base.Background(th.Red).Foreground(th.BgBase).Bold(true).Padding(0, 1),
		container:   base.Foreground(th.FgSubtle),
		process:     base.Foreground(th.Fg),
		metaExec:    base.Foreground(th.Cyan),
		metaDNS:     base.Foreground(th.Green),
		metaAlert:   base.Foreground(th.Red).Bold(true),
	}
}

// Silence unused time import if events are empty.
var _ = time.Now

var _ views.View = (*View)(nil)
