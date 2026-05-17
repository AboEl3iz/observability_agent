// Package graph implements a production-grade in-memory process graph.
//
// # Design goals
//
//  1. Parent ancestry lookup  — O(depth) walk, depth bounded at MaxAncestors=8
//  2. Child tracking          — O(1) parent → children slice via children map
//  3. Session reconstruction  — processes grouped by SID (inferred from ancestry
//     when kernel SID is unavailable)
//  4. Event correlation       — each node carries a fixed-size ring buffer of
//     *event.EventEnvelope references, capped at EventRingCap=32
//
// # Thread safety
//
// All exported methods acquire the internal RWMutex.  Read paths (Lookup,
// Ancestors, Children, Session, Roots, Snapshot) take a read lock; write paths
// (AddFork, AddExec, MarkExit, CorrelateEvent) take a write lock.
//
// # Memory bounds
//
// The graph evicts the oldest nodes (by insertion sequence) when the node
// count exceeds MaxNodes (default 8192).  At ~300 bytes per ProcessNode the
// worst-case heap footprint is ~2.5 MB — acceptable for a long-running agent.
package graph

import (
	"sort"
	"strings"
	"sync"
	"time"

	"ebpf/pkg/event"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// MaxAncestors is the maximum depth of the ancestry walk (matches lineage.MaxAncestorDepth).
	MaxAncestors = 8

	// EventRingCap is the number of correlated event pointers each node can hold.
	// When full, oldest events are overwritten (ring-buffer semantics).
	EventRingCap = 32

	// DefaultMaxNodes is the default LRU eviction threshold.
	DefaultMaxNodes = 8192
)

// ─── Node types ───────────────────────────────────────────────────────────────

// NodeKey uniquely identifies a process across PID-namespace boundaries.
// Using (CgroupID, PID) mirrors the lineage.LineageKey composite key.
type NodeKey struct {
	CgroupID uint64
	PID      uint32
}

// ProcessNode is a single vertex in the process graph.
// Fields are intentionally value-typed (no embedded pointers) to make
// Snapshot copying cheap.
type ProcessNode struct {
	Key           NodeKey
	PPID          uint32
	Comm          string    // short name (TASK_COMM_LEN=16); overwritten on exec
	ExePath       string    // full executable path; set by AddExec
	ContainerName string    // "docker:nginx", "cri:api-server", etc. (empty = host)
	ForkTime      time.Time // wall-clock fork timestamp
	ExecTime      time.Time // wall-clock exec timestamp (zero if no exec seen)

	// Session / process group (set by AddExec when metadata carries them;
	// otherwise inferred from ancestry grouping)
	SID  uint32 // session ID (0 = unknown)
	PGID uint32 // process group ID (0 = unknown)

	// Lifecycle
	IsAlive  bool
	ExitCode int // meaningful only when IsAlive==false

	// Event correlation ring buffer.
	// events[evHead] is the slot to write next; evCount tracks fill level.
	events  [EventRingCap]*event.EventEnvelope
	evHead  int
	evCount int

	// Internal: insertion sequence for LRU eviction ordering.
	seq uint64
}

// EventRing returns a slice of all correlated event pointers, oldest-first.
// The returned slice is a copy — safe to hold without the graph lock.
func (n *ProcessNode) EventRing() []*event.EventEnvelope {
	if n.evCount == 0 {
		return nil
	}
	out := make([]*event.EventEnvelope, n.evCount)
	if n.evCount < EventRingCap {
		copy(out, n.events[:n.evCount])
		return out
	}
	// Ring is full: oldest entry is at evHead.
	for i := 0; i < EventRingCap; i++ {
		out[i] = n.events[(n.evHead+i)%EventRingCap]
	}
	return out
}

// pushEvent appends ev to the ring buffer (caller must hold write lock).
func (n *ProcessNode) pushEvent(ev *event.EventEnvelope) {
	n.events[n.evHead] = ev
	n.evHead = (n.evHead + 1) % EventRingCap
	if n.evCount < EventRingCap {
		n.evCount++
	}
}

// ─── Snapshot (lock-free read-only view) ─────────────────────────────────────

// SnapshotNode is the read-only copy of a ProcessNode exposed to the TUI.
// All slices are freshly allocated so they are safe to iterate without locks.
type SnapshotNode struct {
	Key           NodeKey
	PPID          uint32
	Comm          string
	ExePath       string
	ContainerName string // "docker:nginx", "cri:api-server", etc. (empty = host)
	ForkTime      time.Time
	ExecTime      time.Time
	SID           uint32
	PGID          uint32
	IsAlive       bool
	ExitCode      int
	Events        []*event.EventEnvelope // copy of ring, oldest-first
	Children      []NodeKey              // direct children keys
}

// Snapshot is an immutable point-in-time copy of the graph, safe for
// concurrent reads with no lock held.
type Snapshot struct {
	Nodes    map[NodeKey]*SnapshotNode // all nodes
	Sessions map[uint32][]NodeKey      // SID → node keys
	Roots    []NodeKey                 // top-level nodes (PPID==0 or PPID==1)
	At       time.Time
}

// ─── ProcessGraph ─────────────────────────────────────────────────────────────

// ProcessGraph is the main data structure.
type ProcessGraph struct {
	mu       sync.RWMutex
	nodes    map[NodeKey]*ProcessNode
	children map[NodeKey][]NodeKey // parent → direct children
	sessions map[uint32][]NodeKey  // SID (or inferred group) → members
	maxNodes int
	seq      uint64 // monotonic eviction counter
}

// New constructs a ProcessGraph with the given node cap.
// Pass DefaultMaxNodes for the standard production limit.
func New(maxNodes int) *ProcessGraph {
	if maxNodes <= 0 {
		maxNodes = DefaultMaxNodes
	}
	return &ProcessGraph{
		nodes:    make(map[NodeKey]*ProcessNode, 256),
		children: make(map[NodeKey][]NodeKey, 256),
		sessions: make(map[uint32][]NodeKey),
		maxNodes: maxNodes,
	}
}

// ─── Write paths ──────────────────────────────────────────────────────────────

// AddFork ingests a process_fork event envelope.
// It creates or updates both the child node and (if missing) a stub parent node.
func (g *ProcessGraph) AddFork(env event.EventEnvelope) {
	g.mu.Lock()
	defer g.mu.Unlock()

	childKey := NodeKey{CgroupID: env.CgroupID, PID: env.PID}
	parentKey := NodeKey{CgroupID: env.CgroupID, PID: env.PPID}

	// Ensure parent stub exists (may already be a full node from a prior exec).
	if _, ok := g.nodes[parentKey]; !ok && env.PPID != 0 {
		g.seq++
		g.nodes[parentKey] = &ProcessNode{
			Key:           parentKey,
			PPID:          0, // unknown until its own fork event arrives
			Comm:          env.ParentProcess,
			ContainerName: env.ContainerName,
			IsAlive:       true,
			seq:           g.seq,
		}
		g.evictIfNeeded()
	}

	// Create / update child node.
	child, exists := g.nodes[childKey]
	if !exists {
		g.seq++
		child = &ProcessNode{
			Key: childKey,
			seq: g.seq,
		}
		g.nodes[childKey] = child
		g.evictIfNeeded()
	}
	child.PPID = env.PPID
	child.Comm = env.Process
	child.ContainerName = env.ContainerName
	child.ForkTime = env.Timestamp
	child.IsAlive = true

	// Register child in parent's children list (dedup).
	if !containsKey(g.children[parentKey], childKey) {
		g.children[parentKey] = append(g.children[parentKey], childKey)
	}

	// Session tracking: use SID from metadata if present, else group by PPID.
	if sid, ok := uint32Meta(env.Metadata, "sid"); ok && sid != 0 {
		child.SID = sid
		if !containsKey(g.sessions[sid], childKey) {
			g.sessions[sid] = append(g.sessions[sid], childKey)
		}
	}
	if pgid, ok := uint32Meta(env.Metadata, "pgid"); ok {
		child.PGID = pgid
	}
}

// AddExec ingests an exec event envelope, enriching the existing node with
// the real executable path, updated comm, and exec timestamp.
func (g *ProcessGraph) AddExec(env event.EventEnvelope) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := NodeKey{CgroupID: env.CgroupID, PID: env.PID}
	node, ok := g.nodes[key]
	if !ok {
		// Node not yet known from a fork event — create it.
		g.seq++
		node = &ProcessNode{
			Key:     key,
			PPID:    env.PPID,
			IsAlive: true,
			seq:     g.seq,
		}
		g.nodes[key] = node
		// Register as child of parent.
		parentKey := NodeKey{CgroupID: env.CgroupID, PID: env.PPID}
		if !containsKey(g.children[parentKey], key) {
			g.children[parentKey] = append(g.children[parentKey], key)
		}
		g.evictIfNeeded()
	}
	node.Comm = env.Process
	node.ExecTime = env.Timestamp
	if env.ContainerName != "" {
		node.ContainerName = env.ContainerName
	}
	if path, ok := env.Metadata["full_path"].(string); ok && path != "" {
		node.ExePath = path
	}
	if sid, ok := uint32Meta(env.Metadata, "sid"); ok && sid != 0 {
		if node.SID == 0 {
			node.SID = sid
			if !containsKey(g.sessions[sid], key) {
				g.sessions[sid] = append(g.sessions[sid], key)
			}
		}
	}
}

// MarkExit marks a process as no longer alive.
func (g *ProcessGraph) MarkExit(cgroupID uint64, pid uint32, exitCode int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := NodeKey{CgroupID: cgroupID, PID: pid}
	if n, ok := g.nodes[key]; ok {
		n.IsAlive = false
		n.ExitCode = exitCode
	}
}

// CorrelateEvent attaches a security event to the process node identified by
// (cgroupID, pid). If no node exists, the event is silently dropped.
func (g *ProcessGraph) CorrelateEvent(cgroupID uint64, pid uint32, ev *event.EventEnvelope) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := NodeKey{CgroupID: cgroupID, PID: pid}
	if n, ok := g.nodes[key]; ok {
		n.pushEvent(ev)
	}
}

// ─── Read paths ───────────────────────────────────────────────────────────────

// Lookup returns the node for (cgroupID, pid), or (nil, false) if not found.
func (g *ProcessGraph) Lookup(cgroupID uint64, pid uint32) (*ProcessNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[NodeKey{CgroupID: cgroupID, PID: pid}]
	return n, ok
}

// Ancestors walks the parent chain from (cgroupID, pid) upward, returning
// up to MaxAncestors entries in root-first order. truncated is true when the
// chain was cut at the depth limit.
func (g *ProcessGraph) Ancestors(cgroupID uint64, pid uint32, maxDepth int) ([]*ProcessNode, bool) {
	if maxDepth <= 0 {
		maxDepth = MaxAncestors
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	var chain []*ProcessNode
	key := NodeKey{CgroupID: cgroupID, PID: pid}
	visited := make(map[NodeKey]bool)

	for depth := 0; depth < maxDepth; depth++ {
		node, ok := g.nodes[key]
		if !ok || visited[key] {
			break
		}
		visited[key] = true
		chain = append(chain, node)
		if node.PPID == 0 || node.PPID == 1 || node.PPID == key.PID {
			break
		}
		key = NodeKey{CgroupID: key.CgroupID, PID: node.PPID}
	}

	truncated := len(chain) >= maxDepth
	// Reverse: root ancestor first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, truncated
}

// Children returns the direct children of the node identified by (cgroupID, pid).
func (g *ProcessGraph) Children(cgroupID uint64, pid uint32) []*ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	key := NodeKey{CgroupID: cgroupID, PID: pid}
	keys := g.children[key]
	out := make([]*ProcessNode, 0, len(keys))
	for _, k := range keys {
		if n, ok := g.nodes[k]; ok {
			out = append(out, n)
		}
	}
	return out
}

// Session returns all nodes belonging to the given session ID.
func (g *ProcessGraph) Session(sid uint32) []*ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	keys := g.sessions[sid]
	out := make([]*ProcessNode, 0, len(keys))
	for _, k := range keys {
		if n, ok := g.nodes[k]; ok {
			out = append(out, n)
		}
	}
	return out
}

// Roots returns the top-level process nodes for the given cgroupID
// (i.e. nodes whose PPID is 0, 1, or whose parent is not tracked).
// If cgroupID is 0, roots across all cgroups are returned.
func (g *ProcessGraph) Roots(cgroupID uint64) []*ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*ProcessNode
	for key, n := range g.nodes {
		if cgroupID != 0 && key.CgroupID != cgroupID {
			continue
		}
		parentKey := NodeKey{CgroupID: key.CgroupID, PID: n.PPID}
		_, parentExists := g.nodes[parentKey]
		if n.PPID == 0 || n.PPID == 1 || !parentExists {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ForkTime.Before(out[j].ForkTime)
	})
	return out
}

// NodeCount returns the current number of tracked nodes.
func (g *ProcessGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// ─── Snapshot ────────────────────────────────────────────────────────────────

// Snapshot produces a lock-free, immutable copy of the graph for the TUI.
// The TUI may iterate over the snapshot without holding any lock.
func (g *ProcessGraph) Snapshot() *Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	snap := &Snapshot{
		Nodes:    make(map[NodeKey]*SnapshotNode, len(g.nodes)),
		Sessions: make(map[uint32][]NodeKey, len(g.sessions)),
		At:       time.Now(),
	}

	for key, n := range g.nodes {
		sn := &SnapshotNode{
			Key:           n.Key,
			PPID:          n.PPID,
			Comm:          n.Comm,
			ExePath:       n.ExePath,
			ContainerName: n.ContainerName,
			ForkTime:      n.ForkTime,
			ExecTime:      n.ExecTime,
			SID:           n.SID,
			PGID:          n.PGID,
			IsAlive:       n.IsAlive,
			ExitCode:      n.ExitCode,
			Events:        n.EventRing(),
		}
		// Copy children.
		if ck := g.children[key]; len(ck) > 0 {
			sn.Children = append([]NodeKey(nil), ck...)
		}
		snap.Nodes[key] = sn
	}

	for sid, keys := range g.sessions {
		snap.Sessions[sid] = append([]NodeKey(nil), keys...)
	}

	// Compute roots in snapshot (no node map lock needed — we hold RLock).
	for key, sn := range snap.Nodes {
		parentKey := NodeKey{CgroupID: key.CgroupID, PID: sn.PPID}
		_, parentExists := snap.Nodes[parentKey]
		if sn.PPID == 0 || sn.PPID == 1 || !parentExists {
			snap.Roots = append(snap.Roots, key)
		}
	}
	sort.Slice(snap.Roots, func(i, j int) bool {
		a := snap.Nodes[snap.Roots[i]]
		b := snap.Nodes[snap.Roots[j]]
		return a.ForkTime.Before(b.ForkTime)
	})

	return snap
}

// ─── Snapshot helpers ─────────────────────────────────────────────────────────

// Ancestors walks the snapshot's parent chain from key, returning nodes
// in root-first order.
func (s *Snapshot) Ancestors(key NodeKey) []*SnapshotNode {
	var chain []*SnapshotNode
	visited := make(map[NodeKey]bool)
	cur := key
	for depth := 0; depth < MaxAncestors; depth++ {
		n, ok := s.Nodes[cur]
		if !ok || visited[cur] {
			break
		}
		visited[cur] = true
		chain = append(chain, n)
		if n.PPID == 0 || n.PPID == 1 || n.PPID == cur.PID {
			break
		}
		cur = NodeKey{CgroupID: cur.CgroupID, PID: n.PPID}
	}
	// Reverse to root-first order.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// Children returns the direct children of key within the snapshot.
func (s *Snapshot) Children(key NodeKey) []*SnapshotNode {
	n, ok := s.Nodes[key]
	if !ok {
		return nil
	}
	out := make([]*SnapshotNode, 0, len(n.Children))
	for _, ck := range n.Children {
		if cn, ok := s.Nodes[ck]; ok {
			out = append(out, cn)
		}
	}
	return out
}

// GroupByCgroup groups all snapshot nodes by their CgroupID.
func (s *Snapshot) GroupByCgroup() map[uint64][]*SnapshotNode {
	m := make(map[uint64][]*SnapshotNode)
	for _, n := range s.Nodes {
		m[n.Key.CgroupID] = append(m[n.Key.CgroupID], n)
	}
	return m
}

// RootsForCgroup returns root nodes belonging to a specific cgroup.
func (s *Snapshot) RootsForCgroup(cgroupID uint64) []*SnapshotNode {
	var out []*SnapshotNode
	for _, key := range s.Roots {
		if key.CgroupID == cgroupID {
			if n, ok := s.Nodes[key]; ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// evictIfNeeded removes the node with the lowest sequence number when the
// graph exceeds maxNodes.  Called under write lock.
func (g *ProcessGraph) evictIfNeeded() {
	if len(g.nodes) <= g.maxNodes {
		return
	}
	// Find oldest (lowest seq).
	var oldest NodeKey
	var oldestSeq uint64 = ^uint64(0)
	for k, n := range g.nodes {
		if n.seq < oldestSeq {
			oldestSeq = n.seq
			oldest = k
		}
	}
	// Remove from children lists.
	for pk, ks := range g.children {
		g.children[pk] = removeKey(ks, oldest)
	}
	delete(g.children, oldest)
	// Remove from sessions.
	if n, ok := g.nodes[oldest]; ok && n.SID != 0 {
		g.sessions[n.SID] = removeKey(g.sessions[n.SID], oldest)
	}
	delete(g.nodes, oldest)
}

func containsKey(ks []NodeKey, k NodeKey) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func removeKey(ks []NodeKey, k NodeKey) []NodeKey {
	out := ks[:0]
	for _, x := range ks {
		if x != k {
			out = append(out, x)
		}
	}
	return out
}

// uint32Meta safely extracts a uint32 from an event metadata map.
func uint32Meta(m map[string]any, key string) (uint32, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case uint32:
		return x, true
	case int:
		return uint32(x), true
	case uint64:
		return uint32(x), true
	case float64:
		return uint32(x), true
	}
	return 0, false
}

// DisplayComm returns a human-friendly display name for a node,
// preferring the basename of ExePath over Comm.
func DisplayComm(n *SnapshotNode) string {
	if n.ExePath != "" {
		if idx := strings.LastIndexByte(n.ExePath, '/'); idx >= 0 {
			return n.ExePath[idx+1:]
		}
		return n.ExePath
	}
	return n.Comm
}
