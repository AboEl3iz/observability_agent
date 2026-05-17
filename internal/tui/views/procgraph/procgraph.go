// Package procgraph — Process Graph TUI (tab 9).
//
// Three panels:
//   Left   – Container list
//   Middle – Process tree (PPID-based, cross-cgroup, with box-drawing chars)
//   Right  – Node detail + ancestry breadcrumb + event ring
package procgraph

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpf/internal/tui/msg"
	"ebpf/internal/tui/theme"
	"ebpf/internal/tui/views"
	"ebpf/pkg/event"
	"ebpf/pkg/graph"
)

const (
	panelCgroup = 0
	panelTree   = 1
	panelDetail = 2
)

// treeNode is a rendered, selectable row in the tree panel.
type treeNode struct {
	key     graph.NodeKey
	depth   int
	prefix  string // box-drawing prefix  e.g. "│  ├─ "
	comm    string // display name
	pid     uint32
	hasEvts bool
	evTypes []event.EventType
	alive   bool
}

// View implements views.View for the ProcGraph tab.
type View struct {
	theme       theme.Theme
	w, h        int
	focused     bool
	dirty       bool
	cached      string
	snap        *graph.Snapshot
	cgroupKeys  []string
	cgroupSel   int
	treeLines   []treeNode
	treeSel     int
	treeOffset  int
	activePanel int
	filter      string
}

func New(th theme.Theme) *View {
	return &View{theme: th, activePanel: panelTree, dirty: true}
}

// ─── views.View interface ─────────────────────────────────────────────────────

func (v *View) Init() tea.Cmd                { return nil }
func (v *View) Focus()                       { v.focused = true }
func (v *View) Blur()                        { v.focused = false }
func (v *View) SelectedContainer() string    { return "" }
func (v *View) SetTheme(th theme.Theme)      { v.theme = th; v.invalidate() }
func (v *View) SetSize(w, h int)             { v.w, v.h = w, h; v.rebuildTree(); v.invalidate() }

func (v *View) StatusLine() string {
	nodes := 0
	if v.snap != nil {
		nodes = len(v.snap.Nodes)
	}
	return fmt.Sprintf("ProcGraph [%d nodes]  ·  ←/→ panels  ·  ↑↓/j/k navigate  ·  g/G top/bottom  ·  q quit", nodes)
}

func (v *View) SetData(batch msg.DataBatch) {
	if batch.Graph == nil {
		return
	}
	v.snap = batch.Graph
	v.rebuildCgroupList()
	v.rebuildTree()
	v.invalidate()
}

func (v *View) Update(tmsg tea.Msg) (views.View, tea.Cmd) {
	km, ok := tmsg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}
	switch km.String() {
	case "left", "h":
		if v.activePanel > 0 {
			v.activePanel--
			v.invalidate()
		}
	case "right", "l":
		if v.activePanel < panelDetail {
			v.activePanel++
			v.invalidate()
		}
	case "up", "k":
		v.navUp()
	case "down", "j":
		v.navDown()
	case "g":
		v.navTop()
	case "G":
		v.navBottom()
	}
	return v, nil
}

func (v *View) View() string {
	if !v.dirty && v.cached != "" {
		return v.cached
	}
	v.cached = v.render()
	v.dirty = false
	return v.cached
}

// ─── Navigation ───────────────────────────────────────────────────────────────

func (v *View) navUp() {
	if v.activePanel == panelCgroup {
		if v.cgroupSel > 0 {
			v.cgroupSel--
			v.rebuildTree()
		}
	} else if v.treeSel > 0 {
		v.treeSel--
	}
	v.invalidate()
}

func (v *View) navDown() {
	if v.activePanel == panelCgroup {
		if v.cgroupSel < len(v.cgroupKeys)-1 {
			v.cgroupSel++
			v.rebuildTree()
		}
	} else if v.treeSel < len(v.treeLines)-1 {
		v.treeSel++
	}
	v.invalidate()
}

func (v *View) navTop() {
	if v.activePanel == panelCgroup {
		v.cgroupSel = 0
		v.rebuildTree()
	} else {
		v.treeSel = 0
	}
	v.invalidate()
}

func (v *View) navBottom() {
	if v.activePanel == panelTree && len(v.treeLines) > 0 {
		v.treeSel = len(v.treeLines) - 1
	}
	v.invalidate()
}

func (v *View) invalidate() { v.dirty = true; v.cached = "" }

// ─── Data helpers ─────────────────────────────────────────────────────────────

func cgroupKeyFor(n *graph.SnapshotNode) string {
	if n.ContainerName != "" {
		return n.ContainerName
	}
	return fmt.Sprintf("cg:%d", n.Key.CgroupID)
}

func (v *View) rebuildCgroupList() {
	if v.snap == nil {
		v.cgroupKeys = nil
		return
	}
	seen := make(map[string]bool)
	for _, n := range v.snap.Nodes {
		seen[cgroupKeyFor(n)] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	v.cgroupKeys = keys
	if v.cgroupSel >= len(v.cgroupKeys) {
		v.cgroupSel = 0
	}
}

// rebuildTree builds the process tree for the selected container.
//
// Strategy: build a GLOBAL pid→node map across ALL cgroups in the snapshot,
// then walk from each node that belongs to the selected container upward to
// find its true root (which may be in a different cgroup, e.g. runc/containerd).
// This ensures the tree is hierarchical even when container processes have
// their direct parent (e.g. sh) tracked via exec events only.
func (v *View) rebuildTree() {
	v.treeLines = nil
	if v.snap == nil || len(v.cgroupKeys) == 0 {
		return
	}
	selKey := v.cgroupKeys[v.cgroupSel]

	// ── 1. Global pid→node across ALL cgroups ────────────────────────────────
	// We use (CgroupID,PID) as the unique key but also index by PID alone
	// within the same cgroup for PPID lookup.
	type cgPID struct{ cg uint64; pid uint32 }
	allNodes := make(map[cgPID]*graph.SnapshotNode, len(v.snap.Nodes))
	for k, n := range v.snap.Nodes {
		allNodes[cgPID{k.CgroupID, k.PID}] = n
	}

	// pid lookup within same cgroup
	pidInCg := func(cg uint64, pid uint32) (*graph.SnapshotNode, bool) {
		n, ok := allNodes[cgPID{cg, pid}]
		return n, ok
	}

	// ── 2. Collect nodes for the selected container ───────────────────────────
	var selPIDs []uint32
	selPidMap := make(map[uint32]*graph.SnapshotNode)
	for _, n := range v.snap.Nodes {
		if cgroupKeyFor(n) != selKey {
			continue
		}
		if v.filter != "" && !strings.Contains(
			strings.ToLower(graph.DisplayComm(n)),
			strings.ToLower(v.filter)) {
			continue
		}
		selPidMap[n.Key.PID] = n
		selPIDs = append(selPIDs, n.Key.PID)
	}
	if len(selPIDs) == 0 {
		return
	}

	// ── 3. Build local children map using PPID (within-cgroup first, then cross) ──
	// For each selected node, look for its parent:
	//   a) same cgroup – ideal
	//   b) parent not in same cgroup → node is a root for display purposes
	localKids := make(map[uint32][]uint32)
	isChild := make(map[uint32]bool)
	for _, pid := range selPIDs {
		n := selPidMap[pid]
		if n.PPID == 0 || n.PPID == 1 {
			continue
		}
		// Is parent in the same container?
		if _, ok := selPidMap[n.PPID]; ok && n.PPID != pid {
			localKids[n.PPID] = append(localKids[n.PPID], pid)
			isChild[pid] = true
			continue
		}
		// Is parent in a different cgroup (cross-cgroup parentage)?
		// We show parent node as a dim "host" root above the container.
		if _, ok := pidInCg(n.Key.CgroupID, n.PPID); !ok {
			// Try any cgroup (runc/containerd-shim may have different cgroupID)
			_ = allNodes // allow cross-cgroup lookup below if needed
		}
	}

	// ── 4. Find root PIDs (no parent within selPidMap) ───────────────────────
	var rootPIDs []uint32
	for _, pid := range selPIDs {
		if !isChild[pid] {
			rootPIDs = append(rootPIDs, pid)
		}
	}

	// Stable sort: ForkTime then PID
	sortPIDs := func(pids []uint32, pm map[uint32]*graph.SnapshotNode) {
		sort.Slice(pids, func(i, j int) bool {
			a, b := pm[pids[i]], pm[pids[j]]
			if a == nil || b == nil {
				return pids[i] < pids[j]
			}
			if !a.ForkTime.Equal(b.ForkTime) {
				return a.ForkTime.Before(b.ForkTime)
			}
			return pids[i] < pids[j]
		})
	}
	sortPIDs(rootPIDs, selPidMap)
	for k := range localKids {
		sortPIDs(localKids[k], selPidMap)
	}

	// ── 5. Walk and flatten ───────────────────────────────────────────────────
	visited := make(map[uint32]bool)
	var walk func(pid uint32, prefix string, isLast bool, depth int)
	walk = func(pid uint32, prefix string, isLast bool, depth int) {
		if visited[pid] {
			return
		}
		visited[pid] = true
		n := selPidMap[pid]
		if n == nil {
			return
		}

		// Build box-drawing connector
		var connector string
		if depth > 0 {
			if isLast {
				connector = "└── "
			} else {
				connector = "├── "
			}
		}

		// Collect event type badges
		var evTypes []event.EventType
		seen := make(map[event.EventType]bool)
		for _, ev := range n.Events {
			if ev != nil && !seen[ev.EventType] {
				seen[ev.EventType] = true
				evTypes = append(evTypes, ev.EventType)
			}
		}

		v.treeLines = append(v.treeLines, treeNode{
			key:     n.Key,
			depth:   depth,
			prefix:  prefix + connector,
			comm:    graph.DisplayComm(n),
			pid:     pid,
			hasEvts: len(evTypes) > 0,
			evTypes: evTypes,
			alive:   n.IsAlive,
		})

		// Children's continuation prefix
		var childCont string
		if depth == 0 {
			if isLast {
				childCont = " "
			} else {
				childCont = "│"
			}
		} else {
			if isLast {
				childCont = prefix + "    "
			} else {
				childCont = prefix + "│   "
			}
		}

		kids := localKids[pid]
		for i, k := range kids {
			walk(k, childCont, i == len(kids)-1, depth+1)
		}
	}

	for i, pid := range rootPIDs {
		walk(pid, "", i == len(rootPIDs)-1, 0)
	}

	// Clamp selection
	if v.treeSel >= len(v.treeLines) {
		v.treeSel = 0
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

func (v *View) render() string {
	if v.w == 0 || v.h == 0 {
		return ""
	}
	th := v.theme

	// Title bar
	title := th.PanelTitle.Render("  ◈ Process Graph  ─  Process ancestry, child tracking & event correlation")

	bodyH := v.h - 2
	if bodyH < 4 {
		return title
	}

	// Column widths
	cgW   := 40
	detW  := 34
	treeW := v.w - cgW - detW - 2 // 2 separators
	if treeW < 24 {
		treeW = 24
	}

	left   := v.renderContainerPanel(cgW, bodyH)
	middle := v.renderTreePanel(treeW, bodyH)
	right  := v.renderDetailPanel(detW, bodyH)

	sep  := th.Separator.Render("│")
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, sep, middle, sep, right)
	return lipgloss.JoinVertical(lipgloss.Left, title, body)
}

// ── Container (left) panel ────────────────────────────────────────────────────

func (v *View) renderContainerPanel(w, h int) string {
	th := v.theme
	border := th.PanelBorder
	if v.activePanel == panelCgroup {
		border = th.PanelFocused
	}

	hdr := th.TableHeader.Width(w).Render(" Container")
	var rows []string

	if len(v.cgroupKeys) == 0 {
		rows = append(rows, th.TableDim.Render("  waiting…"))
	}

	for i, key := range v.cgroupKeys {
		count := v.countForKey(key)
		// Leave the container name mostly intact so it appears clearly,
		// only stripping 'cgroup:' or 'host:' which are redundant.
		short := key
		for _, pfx := range []string{"cgroup:", "host:"} {
			if strings.HasPrefix(key, pfx) {
				short = strings.TrimPrefix(key, pfx)
				break
			}
		}
		// Truncate to fit (accounting for icon and count)
		runes := []rune(short)
		maxR := w - 10
		if maxR < 4 {
			maxR = 4
		}
		if len(runes) > maxR {
			short = string(runes[:maxR-1]) + "…"
		}

		label := fmt.Sprintf(" ◉ %s [%d]", short, count)
		style := th.TableRow
		if i == v.cgroupSel {
			style = th.TableSelected
		}
		rows = append(rows, style.Width(w).Render(label))
	}

	for len(rows) < h-2 {
		rows = append(rows, strings.Repeat(" ", w))
	}
	content := hdr + "\n" + strings.Join(rows[:min(len(rows), h-2)], "\n")
	return border.Width(w).Height(h).Render(content)
}

// ── Tree (middle) panel ───────────────────────────────────────────────────────

func (v *View) renderTreePanel(w, h int) string {
	th := v.theme
	border := th.PanelBorder
	if v.activePanel == panelTree {
		border = th.PanelFocused
	}

	hdr := th.TableHeader.Width(w).Render(" Process Tree")

	if len(v.treeLines) == 0 {
		content := hdr + "\n" + th.TableDim.Render("  No processes — select a container")
		return border.Width(w).Height(h).Render(content)
	}

	visH := h - 3 // header + footer
	// Scroll: keep treeSel visible
	if v.treeSel < v.treeOffset {
		v.treeOffset = v.treeSel
	}
	if v.treeSel >= v.treeOffset+visH {
		v.treeOffset = v.treeSel - visH + 1
	}

	var lines []string
	for i := v.treeOffset; i < len(v.treeLines) && len(lines) < visH; i++ {
		tn := &v.treeLines[i]
		node := v.snap.Nodes[tn.key]

		// Build the badge string (emoji, width=2 each)
		badge := v.badgeStr(tn.evTypes)

		// Build comm display: bold if alive, dim if exited
		commDisp := tn.comm
		if !tn.alive {
			commDisp = tn.comm + " ·"
		}

		// Full line: prefix (box chars) + badge + comm + pid
		line := fmt.Sprintf("%s%s%s (%d)", tn.prefix, badge, commDisp, tn.pid)

		// Unicode-safe truncation
		lr := []rune(line)
		maxR := w - 2
		if maxR < 4 {
			maxR = 4
		}
		if len(lr) > maxR {
			line = string(lr[:maxR-1]) + "…"
		}

		// Colour: selected > security event > exited > normal
		var sty lipgloss.Style
		switch {
		case i == v.treeSel:
			sty = th.TableSelected
		case node != nil && len(node.Events) > 0 && !tn.alive:
			sty = th.EventError
		case node != nil && len(node.Events) > 0:
			sty = th.EventSlowSys
		case !tn.alive:
			sty = th.TableDim
		default:
			sty = th.TableRow
		}

		lines = append(lines, sty.Width(w).Render(" "+line))
	}

	for len(lines) < visH {
		lines = append(lines, strings.Repeat(" ", w))
	}

	footer := th.TableDim.Width(w).Render(
		fmt.Sprintf(" [%d/%d]  ↑↓ navigate  ←→ panels", v.treeSel+1, len(v.treeLines)),
	)
	content := hdr + "\n" + strings.Join(lines, "\n") + "\n" + footer
	return border.Width(w).Height(h).Render(content)
}

// ── Detail (right) panel ──────────────────────────────────────────────────────

func (v *View) renderDetailPanel(w, h int) string {
	th := v.theme
	border := th.PanelBorder
	if v.activePanel == panelDetail {
		border = th.PanelFocused
	}

	hdr := th.TableHeader.Width(w).Render(" Node Detail")

	trunc := func(s string, n int) string {
		r := []rune(s)
		if len(r) > n {
			return string(r[:n-1]) + "…"
		}
		return s
	}
	kv := func(k, val string) string {
		return lipgloss.NewStyle().Foreground(th.FgDim).Render(fmt.Sprintf("  %-6s", k)) + " " + th.TableRow.Render(val)
	}

	var lines []string
	if v.snap == nil || len(v.treeLines) == 0 || v.treeSel >= len(v.treeLines) {
		lines = append(lines, th.TableDim.Render("  select a node in the tree"))
		content := hdr + "\n" + strings.Join(lines, "\n")
		return border.Width(w).Height(h).Render(content)
	}

	tn := &v.treeLines[v.treeSel]
	node, ok := v.snap.Nodes[tn.key]
	if !ok {
		lines = append(lines, th.TableDim.Render("  node not found"))
		content := hdr + "\n" + strings.Join(lines, "\n")
		return border.Width(w).Height(h).Render(content)
	}

	lines = append(lines, kv("PID", fmt.Sprintf("%d", node.Key.PID)))
	lines = append(lines, kv("PPID", fmt.Sprintf("%d", node.PPID)))
	lines = append(lines, kv("Comm", trunc(graph.DisplayComm(node), w-10)))
	if node.ContainerName != "" {
		lines = append(lines, kv("Ctr", trunc(node.ContainerName, w-10)))
	}
	if node.ExePath != "" {
		lines = append(lines, kv("Path", trunc(node.ExePath, w-10)))
	}
	if !node.ForkTime.IsZero() {
		lines = append(lines, kv("Fork", node.ForkTime.Format("15:04:05.000")))
	}
	if !node.ExecTime.IsZero() {
		lines = append(lines, kv("Exec", node.ExecTime.Format("15:04:05.000")))
	}
	if node.SID != 0 {
		lines = append(lines, kv("SID", fmt.Sprintf("%d", node.SID)))
	}

	badge := th.BadgeGreen.Render(" alive ")
	if !node.IsAlive {
		badge = th.BadgeDim.Render(fmt.Sprintf(" exit:%d ", node.ExitCode))
	}
	lines = append(lines, "  "+badge, "")

	// ── Ancestry breadcrumb ───────────────────────────────────────────────────
	ancs := v.snap.Ancestors(tn.key)
	if len(ancs) > 0 {
		lines = append(lines, th.PanelTitle.Render("  Ancestry"))
		for i, a := range ancs {
			ind := strings.Repeat("  ", i)
			comm := trunc(graph.DisplayComm(a), w-i*2-6)
			if a.Key == node.Key {
				lines = append(lines, th.TableSelected.Render(ind+"  └─ "+comm+" ◀"))
			} else {
				lines = append(lines, th.TableRow.Render(ind+"  └─ "+comm))
			}
		}
		lines = append(lines, "")
	}

	// ── Correlated events ─────────────────────────────────────────────────────
	evs := node.Events
	if len(evs) > 0 {
		lines = append(lines, th.PanelTitle.Render(fmt.Sprintf("  Events (%d)", len(evs))))
		shown := evs
		if len(shown) > 10 {
			shown = shown[len(shown)-10:]
		}
		for _, ev := range shown {
			if ev == nil {
				continue
			}
			icon, sty := v.evStyle(ev.EventType)
			ts := ev.Timestamp.Format("15:04:05")
			lines = append(lines, sty.Render(fmt.Sprintf("  %s %s %s",
				icon, ts, trunc(ev.Process, w-22))))
		}
	}

	// Pad
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	vis := lines
	if len(vis) > h-2 {
		vis = vis[:h-2]
	}
	content := hdr + "\n" + strings.Join(vis, "\n")
	return border.Width(w).Height(h).Render(content)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// badgeStr returns compact coloured badges for event types on a node.
func (v *View) badgeStr(types []event.EventType) string {
	if len(types) == 0 {
		return ""
	}
	var b strings.Builder
	for _, et := range types {
		switch et {
		case event.EventTypeExec:
			b.WriteString("⚡")
		case event.EventTypePrivEsc:
			b.WriteString("🔒")
		case event.EventTypeDNSQuery:
			b.WriteString("🌐")
		case event.EventTypeEscapeIndicator:
			b.WriteString("🚪")
		}
	}
	if b.Len() > 0 {
		return b.String() + " "
	}
	return ""
}

func (v *View) evStyle(et event.EventType) (string, lipgloss.Style) {
	th := v.theme
	switch et {
	case event.EventTypeExec:
		return "⚡", th.EventInfo
	case event.EventTypePrivEsc:
		return "🔒", th.EventOOM
	case event.EventTypeDNSQuery:
		return "🌐", th.EventTCP
	case event.EventTypeEscapeIndicator:
		return "🚪", th.EventSlowSys
	default:
		return "●", th.TableDim
	}
}

func (v *View) countForKey(key string) int {
	if v.snap == nil {
		return 0
	}
	n := 0
	for _, nd := range v.snap.Nodes {
		if cgroupKeyFor(nd) == key {
			n++
		}
	}
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ views.View = (*View)(nil)
