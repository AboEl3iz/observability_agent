// Package collector — Phase 1: Process Lineage Tracking
//
// LineageCollector implements the lineage.LineageLookup interface.
// It owns:
//   - process_fork_rb  (ring buffer reader): fire-and-forget fork events
//   - process_tree_map (BPF map handle):     live process tree, queryable by other collectors
//
// Map pinning:
//   After loading lineage.o, the Go loader pins process_tree_map to
//   /sys/fs/bpf/ebpf-agent/process_tree_map, then injects it into
//   exec.o, dns.o, privesc.o, escape.o via ebpf.CollectionOptions.MapReplacer.
//   This satisfies the inter-module API contract (requirement 1.12).
//
// Timestamp conversion (requirement 1.8):
//   BPF uses bpf_ktime_get_ns() — nanoseconds since boot, NOT wall clock.
//   Go computes bootTimeOffset at startup: wall_ns = ktime_ns + bootTimeOffset.
//   Applied here in all event parsing.
//
// Depth bounding (requirement 1.7):
//   Tree traversal is bounded to MaxAncestorDepth=8 in Go (not BPF).
//   BPF only stores the immediate parent pointer (ppid). The Ancestors()
//   method walks up the tree iteratively, stopping at depth 8 or a missing entry.
//
// Retention policy (requirement 1.13):
//   - Ring buffer events: consumed on read, dropped on overflow (back-pressure)
//   - process_tree_map: deleted by BPF on main-thread exit (tgid==tid guard)
//     or evicted by LRU at 65,536 entries on high-churn hosts
//   - No Go-side cache in Phase 1 (reads go directly to BPF map via Lookup)
package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/event"
	"ebpf/pkg/lineage"
)

// ---------------------------------------------------------------------------
// BPF map mirror types — must match lineage.c structs exactly
// ---------------------------------------------------------------------------

// lineageKeyBPF mirrors struct lineage_key from lineage.c.
// Used for direct BPF map Lookup calls in the Ancestors() walk.
type lineageKeyBPF struct {
	CgroupID uint64
	TGID     uint32
	Pad      uint32
}

// lineageEntryBPF mirrors struct lineage_entry from lineage.c.
type lineageEntryBPF struct {
	PPID      uint32
	Pad0      uint32
	CgroupID  uint64
	Comm      [16]byte
	ForkTsNs  uint64 // bpf_ktime_get_ns() — NOT wall clock
	CommFinal uint8
	Pad1      [7]byte
}

// forkEventRaw mirrors struct fork_event from lineage.c.
type forkEventRaw struct {
	CgroupID   uint64
	ForkTsNs   uint64
	PPID       uint32
	TGID       uint32
	ParentComm [16]byte
	ChildComm  [16]byte
	CommFinal  uint8
	Pad        [7]byte
}

// ---------------------------------------------------------------------------
// LineageCollector
// ---------------------------------------------------------------------------

// LineageCollector implements lineage.LineageLookup.
// It is safe for concurrent use: BPF map lookups are atomic, and the
// ring buffer is drained by a single goroutine in the main poll loop.
type LineageCollector struct {
	forkRB       *ringbuf.Reader
	treeMap      *ebpf.Map // process_tree_map (LRU_HASH)
	resolver     *cgroup.Resolver
	writer       event.SecurityEventWriter
	bootOffset   int64 // nanoseconds: wall_ns = ktime_ns + bootOffset
	log          *slog.Logger
}

// NewLineageCollector creates a LineageCollector.
//   - forkRBMap:  BPF map "process_fork_rb" (ring buffer)
//   - treeMap:    BPF map "process_tree_map" (LRU_HASH, shared with other modules)
//   - resolver:   cgroup resolver for container name enrichment
//   - writer:     security event output (nil = suppress output)
//   - bootOffset: nanosecond offset for ktime→wall-clock conversion
func NewLineageCollector(
	forkRBMap *ebpf.Map, // may be nil — ring buffer is optional
	treeMap *ebpf.Map,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*LineageCollector, error) {
	var rd *ringbuf.Reader
	if forkRBMap != nil {
		var err error
		rd, err = ringbuf.NewReader(forkRBMap)
		if err != nil {
			return nil, fmt.Errorf("opening process_fork_rb ring buffer: %w", err)
		}
	}
	return &LineageCollector{
		forkRB:     rd,
		treeMap:    treeMap,
		resolver:   resolver,
		writer:     writer,
		bootOffset: bootOffset,
		log:        log,
	}, nil
}

// Close releases the ring buffer reader.
func (c *LineageCollector) Close() {
	if c.forkRB != nil {
		c.forkRB.Close()
	}
}

// ---------------------------------------------------------------------------
// lineage.LineageLookup implementation
// ---------------------------------------------------------------------------

// Lookup returns the lineage entry for (cgroupID, tgid).
// Reads directly from the BPF LRU hash map — no Go-side cache.
// Returns false if the process has exited, was never tracked, or evicted by LRU.
func (c *LineageCollector) Lookup(cgroupID uint64, tgid uint32) (lineage.LineageEntry, bool) {
	key := lineageKeyBPF{CgroupID: cgroupID, TGID: tgid}
	var val lineageEntryBPF
	if err := c.treeMap.Lookup(&key, &val); err != nil {
		return lineage.LineageEntry{}, false
	}
	return c.toLineageEntry(&val), true
}

// Ancestors walks the parent chain from (cgroupID, tgid) upward, returning
// up to maxDepth entries oldest-first (root → direct parent).
// truncated is true when the chain exceeded maxDepth.
//
// Depth limit is enforced here in Go (requirement 1.7):
// BPF only stores immediate parent pointer. No BPF-side loop needed.
func (c *LineageCollector) Ancestors(cgroupID uint64, tgid uint32, maxDepth int) ([]lineage.LineageEntry, bool) {
	if maxDepth <= 0 {
		maxDepth = lineage.MaxAncestorDepth
	}

	var chain []lineage.LineageEntry
	truncated := false

	currentCgroup := cgroupID
	currentTGID := tgid

	for depth := 0; depth < maxDepth; depth++ {
		entry, ok := c.Lookup(currentCgroup, currentTGID)
		if !ok {
			break // process exited, untracked, or evicted
		}
		chain = append(chain, entry)

		// Stop at root (ppid == 0 or ppid == 1 or ppid == self)
		if entry.PPID == 0 || entry.PPID == 1 || entry.PPID == currentTGID {
			break
		}

		// Walk up: parent is in the same cgroup (best effort — cross-cgroup forks
		// may not be traceable via this map alone)
		currentTGID = entry.PPID
		// Parent's cgroup_id may differ if it's in a different container.
		// Look it up from the parent's lineage entry.
		parentKey := lineageKeyBPF{CgroupID: currentCgroup, TGID: currentTGID}
		var parentVal lineageEntryBPF
		if err := c.treeMap.Lookup(&parentKey, &parentVal); err != nil {
			// Try same cgroup — the parent lives in a different cgroup (e.g., host)
			break
		}
		currentCgroup = parentVal.CgroupID
	}

	// Detect truncation: if we hit maxDepth without finding a root
	if len(chain) >= maxDepth {
		// Try one more level to check if there are more ancestors
		if len(chain) > 0 {
			last := chain[len(chain)-1]
			if last.PPID != 0 && last.PPID != 1 {
				truncated = true
			}
		}
	}

	// Reverse so oldest (root) is first
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	return chain, truncated
}

// ---------------------------------------------------------------------------
// Ring buffer drain
// ---------------------------------------------------------------------------

// ReadForkEvents drains all pending fork events from process_fork_rb.
// Each event is converted to an EventEnvelope and emitted via the writer.
// Returns the raw slice for callers that need to inspect events directly.
func (c *LineageCollector) ReadForkEvents() ([]event.EventEnvelope, error) {
	if c.forkRB == nil {
		return nil, nil // no ring buffer in map-only mode
	}
	var events []event.EventEnvelope
	rawSize := int(unsafe.Sizeof(forkEventRaw{}))
	for {
		c.forkRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.forkRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			c.log.Warn("short process_fork_rb record", "len", len(rec.RawSample), "want", rawSize)
			continue
		}
		raw := parseForkEvent(rec.RawSample)
		env := c.forkEventToEnvelope(&raw)
		events = append(events, env)
		if c.writer != nil {
			c.writer.Write(env)
		}
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (c *LineageCollector) toLineageEntry(v *lineageEntryBPF) lineage.LineageEntry {
	forkWall := time.Unix(0, int64(v.ForkTsNs)+c.bootOffset).UTC()
	return lineage.LineageEntry{
		PPID:      v.PPID,
		CgroupID:  v.CgroupID,
		Comm:      nullTermStr(v.Comm[:]),
		ForkTime:  forkWall,
		CommFinal: v.CommFinal == 1,
	}
}

func (c *LineageCollector) forkEventToEnvelope(raw *forkEventRaw) event.EventEnvelope {
	forkWall := time.Unix(0, int64(raw.ForkTsNs)+c.bootOffset).UTC()

	name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
	if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
		name = info.Name
	}

	parentComm := nullTermStr(raw.ParentComm[:])
	childComm  := nullTermStr(raw.ChildComm[:])

	return event.EventEnvelope{
		Timestamp:     forkWall,
		CgroupID:      raw.CgroupID,
		ContainerName: name,
		PID:           raw.TGID,
		PPID:          raw.PPID,
		Process:       childComm,
		ParentProcess: parentComm,
		EventType:     event.EventTypeFork,
		Metadata: map[string]any{
			"container":       name,
			"child_comm_final": raw.CommFinal == 1,
		},
	}
}

func parseForkEvent(data []byte) forkEventRaw {
	var r forkEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.ForkTsNs = binary.LittleEndian.Uint64(data[8:16])
	r.PPID     = binary.LittleEndian.Uint32(data[16:20])
	r.TGID     = binary.LittleEndian.Uint32(data[20:24])
	copy(r.ParentComm[:], data[24:40])
	copy(r.ChildComm[:], data[40:56])
	r.CommFinal = data[56]
	return r
}


