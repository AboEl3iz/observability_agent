// Package collector — M2: Memory & OOM Kill Root Cause
//
// The MemoryCollector does two things:
//
//  1. Polls the BPF hash map `page_fault_map` every interval to produce
//     per-container page fault rates.
//
//  2. Runs a background goroutine that drains the BPF ring buffer `oom_events`
//     and emits structured OOM kill reports (container name, victim PID,
//     memory limit, current usage) to a caller-supplied channel.
//
// Metrics produced:
//
//	container_page_faults_total      – cumulative user page faults per container
//	container_memory_bytes           – current RSS from cgroupfs memory.current
//	container_memory_limit_bytes     – limit from cgroupfs memory.max
package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
)

// ---------------------------------------------------------------------------
// BPF map mirror types
// ---------------------------------------------------------------------------

// PfStats mirrors the BPF struct pf_stats.
type PfStats struct {
	Faults uint64
}

// oomEventRaw is the on-wire layout of struct oom_event from memory.c.
// Must match exactly (little-endian, no padding surprises).
type oomEventRaw struct {
	CgroupID   uint64
	VictimPID  uint32
	OOMScoreAdj uint32
	Pages      uint64
	Comm       [16]byte
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// MemSample is a per-container memory snapshot.
type MemSample struct {
	CgroupID      uint64
	ContainerName string
	// Page faults
	Faults        uint64
	FaultsPerSec  float64
	// cgroupfs memory stats (0 if unreadable)
	MemoryBytes     uint64
	MemoryLimitBytes uint64

	CollectedAt time.Time
}

// OOMEvent carries the structured OOM kill information.
type OOMEvent struct {
	Timestamp     time.Time
	CgroupID      uint64
	ContainerName string
	VictimPID     uint32
	OOMScoreAdj   int32
	Pages         uint64
	Comm          string
	// Enriched from cgroupfs
	MemoryBytes     uint64
	MemoryLimitBytes uint64
	SwapBytes       uint64
}

// MemoryCollector polls BPF maps for memory metrics and streams OOM events.
type MemoryCollector struct {
	pfMap    *ebpf.Map
	oomRB    *ringbuf.Reader
	resolver *cgroup.Resolver
	log      *slog.Logger

	mu        sync.Mutex
	prev      map[uint64]PfStats
	prevAt    time.Time
	oomEvents []OOMEvent
}

// NewMemoryCollector creates a MemoryCollector.
//   - pfMap   : BPF map "page_fault_map"
//   - oomMap  : BPF map "oom_events" (ring buffer)
//   - resolver: cgroup resolver (M0)
func NewMemoryCollector(pfMap *ebpf.Map, oomMap *ebpf.Map, resolver *cgroup.Resolver, log *slog.Logger) (*MemoryCollector, error) {
	rd, err := ringbuf.NewReader(oomMap)
	if err != nil {
		return nil, fmt.Errorf("opening oom_events ring buffer: %w", err)
	}
	m := &MemoryCollector{
		pfMap:    pfMap,
		oomRB:    rd,
		resolver: resolver,
		log:      log,
		prev:     make(map[uint64]PfStats),
	}
	go m.startOOMReader()
	return m, nil
}

// Close releases the ring buffer reader.
func (m *MemoryCollector) Close() {
	if m.oomRB != nil {
		m.oomRB.Close()
	}
}

// Collect reads the page_fault_map and cgroupfs, returning per-container samples.
func (m *MemoryCollector) Collect() ([]MemSample, error) {
	now := time.Now()

	m.mu.Lock()
	elapsed := now.Sub(m.prevAt).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	m.mu.Unlock()

	var samples []MemSample
	var cgroupID uint64
	var val PfStats

	iter := m.pfMap.Iterate()
	for iter.Next(&cgroupID, &val) {
		name := fmt.Sprintf("cgroup:%d", cgroupID)
		var cgPath string
		info, ok := m.resolver.Lookup(cgroupID)
		if ok {
			name = info.Name
			cgPath = info.CgroupPath
		} else {
			// Dead container and history expired -> evict from BPF map to save kernel memory
			_ = m.pfMap.Delete(&cgroupID)
			continue
		}

		sample := MemSample{
			CgroupID:      cgroupID,
			ContainerName: name,
			Faults:        val.Faults,
			CollectedAt:   now,
		}

		m.mu.Lock()
		if prev, ok := m.prev[cgroupID]; ok {
			delta := saturatingSubU64(val.Faults, prev.Faults)
			sample.FaultsPerSec = float64(delta) / elapsed
		}
		m.mu.Unlock()

		// Enrich from cgroupfs (non-fatal)
		if cgPath != "" {
			sample.MemoryBytes = readCgroupUint64(cgPath, "memory.current")
			sample.MemoryLimitBytes = readCgroupUint64(cgPath, "memory.max")
		}

		samples = append(samples, sample)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating page_fault_map: %w", err)
	}

	// Update previous snapshot
	m.mu.Lock()
	m.prev = make(map[uint64]PfStats, len(samples))
	for _, s := range samples {
		m.prev[s.CgroupID] = PfStats{Faults: s.Faults}
	}
	m.prevAt = now
	m.mu.Unlock()

	return samples, nil
}

// ReadOOMEvents drains all pending OOM events from the ring buffer.
// Non-blocking: returns whatever is available right now.
func (m *MemoryCollector) ReadOOMEvents() ([]OOMEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.oomEvents
	m.oomEvents = nil
	return events, nil
}

func (m *MemoryCollector) startOOMReader() {
	m.log.Info("🚀 OOM reader goroutine started successfully!")
	const rawSize = int(unsafe.Sizeof(oomEventRaw{}))
	for {
		m.log.Info("⏳ OOM reader blocking on Read()...")
		rec, err := m.oomRB.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.log.Info("🛑 OOM reader ringbuffer closed, exiting goroutine")
				return
			}
			m.log.Error("error reading from OOM ringbuf", "err", err)
			continue
		}

		m.log.Info("🎉 OOM reader unblocked! Read record from BPF!", "len", len(rec.RawSample))

		if len(rec.RawSample) < rawSize {
			m.log.Warn("short OOM ring buffer record", "len", len(rec.RawSample))
			continue
		}

		raw := parseOOMEvent(rec.RawSample)
		name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
		var cgPath string
		if info, ok := m.resolver.Lookup(raw.CgroupID); ok {
			name = info.Name
			cgPath = info.CgroupPath
		}

		ev := OOMEvent{
			Timestamp:     time.Now(),
			CgroupID:      raw.CgroupID,
			ContainerName: name,
			VictimPID:     raw.VictimPID,
			OOMScoreAdj:   int32(raw.OOMScoreAdj),
			Pages:         raw.Pages,
			Comm:          commString(raw.Comm[:]),
		}

		if cgPath != "" {
			ev.MemoryBytes = readCgroupUint64(cgPath, "memory.current")
			ev.MemoryLimitBytes = readCgroupUint64(cgPath, "memory.max")
			ev.SwapBytes = readCgroupUint64(cgPath, "memory.swap.current")
		}

		m.mu.Lock()
		m.oomEvents = append(m.oomEvents, ev)
		m.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func parseOOMEvent(data []byte) oomEventRaw {
	var r oomEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.VictimPID = binary.LittleEndian.Uint32(data[8:12])
	r.OOMScoreAdj = binary.LittleEndian.Uint32(data[12:16])
	r.Pages = binary.LittleEndian.Uint64(data[16:24])
	copy(r.Comm[:], data[24:40])
	return r
}

func commString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// readCgroupUint64 reads a uint64 value from a cgroupfs file.
// Returns 0 for "max" (unlimited) and on any error.
func readCgroupUint64(cgPath, filename string) uint64 {
	full := filepath.Join("/sys/fs/cgroup", cgPath, filename)
	data, err := os.ReadFile(full)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0 // treat "unlimited" as 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func saturatingSubU64(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
