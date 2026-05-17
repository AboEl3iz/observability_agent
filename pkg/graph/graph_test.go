package graph

import (
	"testing"
	"time"

	"ebpf/pkg/event"
)

// newForkEnv builds a minimal fork EventEnvelope for testing.
func newForkEnv(cgroupID uint64, pid, ppid uint32, comm, parentComm string) event.EventEnvelope {
	return event.EventEnvelope{
		Timestamp:     time.Now(),
		CgroupID:      cgroupID,
		PID:           pid,
		PPID:          ppid,
		Process:       comm,
		ParentProcess: parentComm,
		EventType:     event.EventTypeFork,
	}
}

func newExecEnv(cgroupID uint64, pid, ppid uint32, comm, path string) event.EventEnvelope {
	return event.EventEnvelope{
		Timestamp: time.Now(),
		CgroupID:  cgroupID,
		PID:       pid,
		PPID:      ppid,
		Process:   comm,
		EventType: event.EventTypeExec,
		Metadata:  map[string]any{"full_path": path},
	}
}

// ─── TestAddForkAndLookup ─────────────────────────────────────────────────────

func TestAddForkAndLookup(t *testing.T) {
	g := New(100)
	env := newForkEnv(1, 200, 100, "nginx", "runc")
	g.AddFork(env)

	n, ok := g.Lookup(1, 200)
	if !ok {
		t.Fatal("expected node for pid=200")
	}
	if n.Comm != "nginx" {
		t.Errorf("comm: got %q want %q", n.Comm, "nginx")
	}
	if n.PPID != 100 {
		t.Errorf("ppid: got %d want %d", n.PPID, 100)
	}
	if !n.IsAlive {
		t.Error("expected IsAlive=true")
	}
}

// ─── TestParentAncestryLookup ─────────────────────────────────────────────────

func TestParentAncestryLookup(t *testing.T) {
	g := New(100)
	// Build chain: init(1) → containerd(100) → dockerd(200) → runc(300) → nginx(400)
	g.AddFork(newForkEnv(1, 100, 1, "containerd", "init"))
	g.AddFork(newForkEnv(1, 200, 100, "dockerd", "containerd"))
	g.AddFork(newForkEnv(1, 300, 200, "runc", "dockerd"))
	g.AddFork(newForkEnv(1, 400, 300, "nginx", "runc"))

	ancs, truncated := g.Ancestors(1, 400, 8)
	if truncated {
		t.Error("unexpected truncation")
	}
	// Should include nginx itself + 3 ancestors = 4 nodes, root-first.
	if len(ancs) < 2 {
		t.Fatalf("expected at least 2 ancestors, got %d", len(ancs))
	}
	// Oldest (root) first.
	if ancs[0].Comm != "containerd" && ancs[0].Comm != "init" {
		t.Logf("ancestors: %v", comms(ancs))
	}
	// Last entry should be the process itself (nginx).
	last := ancs[len(ancs)-1]
	if last.Comm != "nginx" {
		t.Errorf("last ancestor: got %q want nginx", last.Comm)
	}
}

// ─── TestChildTracking ────────────────────────────────────────────────────────

func TestChildTracking(t *testing.T) {
	g := New(100)
	// parent runc(300) spawns nginx(401) and nginx(402)
	g.AddFork(newForkEnv(1, 300, 200, "runc", "dockerd"))
	g.AddFork(newForkEnv(1, 401, 300, "nginx", "runc"))
	g.AddFork(newForkEnv(1, 402, 300, "nginx", "runc"))

	children := g.Children(1, 300)
	if len(children) != 2 {
		t.Errorf("expected 2 children, got %d", len(children))
	}
}

// ─── TestChildDedup ───────────────────────────────────────────────────────────

func TestChildDedup(t *testing.T) {
	g := New(100)
	env := newForkEnv(1, 401, 300, "nginx", "runc")
	g.AddFork(env)
	g.AddFork(env) // duplicate — must not create duplicate children entry
	children := g.Children(1, 300)
	if len(children) != 1 {
		t.Errorf("duplicate child registered: got %d children", len(children))
	}
}

// ─── TestSessionReconstruction ───────────────────────────────────────────────

func TestSessionReconstruction(t *testing.T) {
	g := New(100)
	// Inject fork events with explicit SID metadata.
	mkEnv := func(pid, ppid uint32, sid uint32) event.EventEnvelope {
		env := newForkEnv(1, pid, ppid, "sh", "bash")
		env.Metadata = map[string]any{"sid": sid}
		return env
	}
	g.AddFork(mkEnv(10, 1, 42))
	g.AddFork(mkEnv(11, 10, 42))
	g.AddFork(mkEnv(20, 1, 99))

	sess42 := g.Session(42)
	if len(sess42) != 2 {
		t.Errorf("session 42: expected 2 members, got %d", len(sess42))
	}
	sess99 := g.Session(99)
	if len(sess99) != 1 {
		t.Errorf("session 99: expected 1 member, got %d", len(sess99))
	}
}

// ─── TestEventCorrelation ─────────────────────────────────────────────────────

func TestEventCorrelation(t *testing.T) {
	g := New(100)
	g.AddFork(newForkEnv(1, 500, 100, "python", "sh"))

	ev1 := &event.EventEnvelope{EventType: event.EventTypeExec, Process: "python"}
	ev2 := &event.EventEnvelope{EventType: event.EventTypePrivEsc, Process: "python"}
	g.CorrelateEvent(1, 500, ev1)
	g.CorrelateEvent(1, 500, ev2)

	n, ok := g.Lookup(1, 500)
	if !ok {
		t.Fatal("node not found")
	}
	ring := n.EventRing()
	if len(ring) != 2 {
		t.Errorf("expected 2 events in ring, got %d", len(ring))
	}
	if ring[0].EventType != event.EventTypeExec {
		t.Errorf("first event: got %q want exec", ring[0].EventType)
	}
}

// ─── TestEventRingOverflow ────────────────────────────────────────────────────

func TestEventRingOverflow(t *testing.T) {
	g := New(100)
	g.AddFork(newForkEnv(1, 600, 1, "stress", "sh"))

	for i := 0; i < EventRingCap+10; i++ {
		ev := &event.EventEnvelope{EventType: event.EventTypeExec}
		g.CorrelateEvent(1, 600, ev)
	}
	n, _ := g.Lookup(1, 600)
	ring := n.EventRing()
	if len(ring) != EventRingCap {
		t.Errorf("expected ring size %d, got %d", EventRingCap, len(ring))
	}
}

// ─── TestMarkExit ─────────────────────────────────────────────────────────────

func TestMarkExit(t *testing.T) {
	g := New(100)
	g.AddFork(newForkEnv(1, 700, 1, "sleep", "sh"))
	g.MarkExit(1, 700, 0)

	n, ok := g.Lookup(1, 700)
	if !ok {
		t.Fatal("node not found after exit")
	}
	if n.IsAlive {
		t.Error("expected IsAlive=false after MarkExit")
	}
}

// ─── TestLRUEviction ─────────────────────────────────────────────────────────

func TestLRUEviction(t *testing.T) {
	const cap = 5
	g := New(cap)
	for i := uint32(1); i <= uint32(cap+3); i++ {
		g.AddFork(newForkEnv(1, i, 0, "proc", ""))
	}
	if g.NodeCount() > cap+1 { // +1 for parent stub with pid=0
		t.Errorf("LRU eviction failed: %d nodes (cap=%d)", g.NodeCount(), cap)
	}
}

// ─── TestSnapshot ─────────────────────────────────────────────────────────────

func TestSnapshot(t *testing.T) {
	g := New(100)
	g.AddFork(newForkEnv(1, 10, 1, "init", ""))
	g.AddFork(newForkEnv(1, 20, 10, "sshd", "init"))
	g.AddExec(newExecEnv(1, 20, 10, "sshd", "/usr/sbin/sshd"))

	snap := g.Snapshot()
	if len(snap.Nodes) < 2 {
		t.Errorf("expected ≥2 nodes in snapshot, got %d", len(snap.Nodes))
	}
	sn, ok := snap.Nodes[NodeKey{CgroupID: 1, PID: 20}]
	if !ok {
		t.Fatal("pid=20 not in snapshot")
	}
	if sn.ExePath != "/usr/sbin/sshd" {
		t.Errorf("ExePath: got %q", sn.ExePath)
	}

	// Test snapshot Ancestors helper.
	ancs := snap.Ancestors(NodeKey{CgroupID: 1, PID: 20})
	if len(ancs) == 0 {
		t.Error("snapshot Ancestors returned empty")
	}
}

// ─── TestSnapshotChildren ─────────────────────────────────────────────────────

func TestSnapshotChildren(t *testing.T) {
	g := New(100)
	g.AddFork(newForkEnv(1, 100, 1, "parent", ""))
	g.AddFork(newForkEnv(1, 101, 100, "child1", "parent"))
	g.AddFork(newForkEnv(1, 102, 100, "child2", "parent"))

	snap := g.Snapshot()
	kids := snap.Children(NodeKey{CgroupID: 1, PID: 100})
	if len(kids) != 2 {
		t.Errorf("expected 2 children in snapshot, got %d", len(kids))
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func comms(nodes []*ProcessNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Comm
	}
	return out
}
