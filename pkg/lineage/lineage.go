// Package lineage defines the public API contract for the Process Lineage
// module (Phase 1). All downstream security modules (Phase 2–5) access
// process ancestry exclusively through the LineageLookup interface —
// they never read process_tree_map directly.
//
// This decoupling allows the lineage store to evolve (e.g., add a Go-side
// cache, switch to pid_ns_ino keying) without touching downstream collectors.
package lineage

import "time"

// LineageKey mirrors struct lineage_key from ebpf/lineage.c.
// The composite key is (cgroup_id, tgid) to be PID-namespace safe:
// two containers can both have tgid=100, but they will have different cgroup IDs.
//
// Kernel version requirement: ≥5.8 (ring buffer baseline, cgroup_id since 5.5).
type LineageKey struct {
	CgroupID uint64
	TGID     uint32
	Pad      uint32
}

// LineageEntry mirrors struct lineage_entry from ebpf/lineage.c.
// comm_final=false means the process has forked but not yet called execve;
// the Comm field holds the parent's name as a placeholder.
// Phase 2 (exec.c / ExecCollector) sets CommFinal=true with the real executable.
type LineageEntry struct {
	PPID      uint32
	CgroupID  uint64
	Comm      string    // TASK_COMM_LEN=16; placeholder until CommFinal=true
	ForkTime  time.Time // wall-clock (converted from bpf_ktime_get_ns by collector)
	CommFinal bool      // false = placeholder comm; true = real executable name
}

// MaxAncestorDepth is the maximum number of ancestor levels returned by
// Ancestors(). When the chain is longer, truncated=true is set on the event.
// Depth limit is enforced in Go userspace (Ancestors method), not in BPF.
// This keeps BPF complexity minimal while still bounding traversal cost.
const MaxAncestorDepth = 8

// LineageLookup is the public API for the Process Lineage module.
// All Phase 2–5 collectors receive this interface at construction time.
//
// Implementations must be safe for concurrent use from multiple goroutines.
type LineageLookup interface {
	// Lookup returns the lineage entry for (cgroupID, tgid).
	// Returns false if the process has exited, was never tracked, or the
	// entry was evicted from the LRU map.
	Lookup(cgroupID uint64, tgid uint32) (LineageEntry, bool)

	// Ancestors walks the parent chain from (cgroupID, tgid) upward, returning
	// up to maxDepth entries oldest-first (root ancestor first, direct parent last).
	// truncated is true when the chain exceeded maxDepth.
	//
	// Callers should pass lineage.MaxAncestorDepth as maxDepth unless there
	// is a specific reason to use a smaller bound.
	Ancestors(cgroupID uint64, tgid uint32, maxDepth int) (entries []LineageEntry, truncated bool)
}
