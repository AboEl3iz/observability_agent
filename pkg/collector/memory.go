// Package collector — M2: Memory & OOM Kill Root Cause
//
// The MemoryCollector does two things:
//
//  1. Polls the BPF hash map `page_fault_map` every interval to produce
//     per-container page fault rates (minor and major separately).
//
//  2. Runs a background goroutine that drains the BPF ring buffer `oom_events`
//     and emits structured OOM kill reports (container name, victim PID,
//     memory limit, current usage) to a caller-supplied channel.
//
// Metrics produced:
//
//	container_page_faults_minor_total  – cumulative minor user page faults
//	container_page_faults_major_total  – cumulative major user page faults
//	container_memory_bytes             – current RSS from cgroupfs memory.current
//	container_memory_limit_bytes       – limit from cgroupfs memory.max
//	container_memory_virt_bytes        – virtual address space from /proc/<pid>/status (opt-in)
//	container_memory_pss_bytes         – proportional set size from smaps_rollup (opt-in)
//	container_memory_shared_bytes      – shared pages from smaps_rollup (opt-in)
//	container_psi_some_pct             – PSI memory pressure some% avg10
//	container_psi_full_pct             – PSI memory pressure full% avg10
package collector

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
)

// ---------------------------------------------------------------------------
// BPF map mirror types
// ---------------------------------------------------------------------------

// PfStats mirrors the BPF struct pf_stats (minor + major split).
// Must match the layout of struct pf_stats in memory.c exactly.
type PfStats struct {
	MinorFaults uint64
	MajorFaults uint64
}

// oomEventRaw is the on-wire layout of struct oom_event from memory.c.
// Must match exactly (little-endian, no padding surprises).
type oomEventRaw struct {
	CgroupID    uint64
	VictimPID   uint32
	OOMScoreAdj uint32
	Pages       uint64
	Comm        [16]byte
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// MemSample is a per-container memory snapshot.
type MemSample struct {
	CgroupID      uint64
	ContainerName string

	// Page faults from BPF (split minor / major)
	MinorFaults uint64
	MajorFaults uint64
	MinorPerSec float64
	MajorPerSec float64
	// Total faults/s kept for backward compat (minor + major)
	FaultsPerSec float64

	// cgroupfs memory stats (0 if unreadable)
	MemoryBytes      uint64
	MemoryLimitBytes uint64

	// Procfs-sourced (populated only when MemoryCollector.RichMem=true)
	VirtBytes   uint64 // virtual memory size (VmSize from /proc/<pid>/status)
	PSSBytes    uint64 // proportional set size (smaps_rollup Pss)
	SharedBytes uint64 // shared pages (smaps_rollup Shared_Clean + Shared_Dirty)

	// PSI memory pressure (from /sys/fs/cgroup/<cg>/memory.pressure avg10)
	PSISome float64 // some% — at least one task stalled on memory
	PSIFull float64 // full% — all tasks stalled on memory

	// TLB miss rate proxy: minor faults/s
	// Minor faults = page present but TLB stale → cache miss resolved without disk.
	TLBMissRate float64

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
	MemoryBytes      uint64
	MemoryLimitBytes uint64
	SwapBytes        uint64
}

// MemoryCollector polls BPF maps for memory metrics and streams OOM events.
type MemoryCollector struct {
	pfMap    *ebpf.Map
	oomRB    *ringbuf.Reader
	resolver *cgroup.Resolver
	log      *slog.Logger

	// RichMem enables PSS/VIRT/Shared collection via /proc/<pid>/smaps_rollup.
	// It adds per-poll I/O (one file read per PID in cgroup), so it's opt-in.
	RichMem bool

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

	var toDelete []uint64
	iter := m.pfMap.Iterate()
	for iter.Next(&cgroupID, &val) {
		name := fmt.Sprintf("cgroup:%d", cgroupID)
		var cgPath string
		info, ok := m.resolver.Lookup(cgroupID)
		if ok {
			name = info.Name
			cgPath = info.CgroupPath
		} else {
			// Dead container and history expired → evict from BPF map to save kernel memory
			toDelete = append(toDelete, cgroupID)
			continue
		}

		sample := MemSample{
			CgroupID:      cgroupID,
			ContainerName: name,
			MinorFaults:   val.MinorFaults,
			MajorFaults:   val.MajorFaults,
			CollectedAt:   now,
		}

		m.mu.Lock()
		if prev, ok := m.prev[cgroupID]; ok {
			deltaMinor := saturatingSubU64(val.MinorFaults, prev.MinorFaults)
			deltaMajor := saturatingSubU64(val.MajorFaults, prev.MajorFaults)
			sample.MinorPerSec = float64(deltaMinor) / elapsed
			sample.MajorPerSec = float64(deltaMajor) / elapsed
			sample.FaultsPerSec = sample.MinorPerSec + sample.MajorPerSec
			// TLB miss proxy: minor faults resolve without disk → they represent
			// TLB/cache misses for pages already in memory (anon CoW, shared libs, etc.)
			sample.TLBMissRate = sample.MinorPerSec
		}
		m.mu.Unlock()

		// Enrich from cgroupfs (non-fatal)
		if cgPath != "" {
			sample.MemoryBytes = readCgroupUint64(cgPath, "memory.current")
			sample.MemoryLimitBytes = readCgroupUint64(cgPath, "memory.max")
			sample.PSISome, sample.PSIFull = readMemoryPSI(cgPath)

			// Rich procfs scan (VIRT / PSS / Shared) — opt-in due to I/O cost
			if m.RichMem {
				virt, pss, shared := readProcMemStats(cgPath)
				sample.VirtBytes = virt
				sample.PSSBytes = pss
				sample.SharedBytes = shared
			}
		}

		samples = append(samples, sample)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating page_fault_map: %w", err)
	}

	for _, id := range toDelete {
		_ = m.pfMap.Delete(&id)
	}

	// Update previous snapshot
	m.mu.Lock()
	m.prev = make(map[uint64]PfStats, len(samples))
	for _, s := range samples {
		m.prev[s.CgroupID] = PfStats{
			MinorFaults: s.MinorFaults,
			MajorFaults: s.MajorFaults,
		}
	}
	m.prevAt = now
	m.mu.Unlock()

	return samples, nil
}

// ReadOOMEvents drains all pending OOM events collected by the background reader.
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

// readMemoryPSI reads /sys/fs/cgroup/<cg>/memory.pressure and returns
// the avg10 some% and full% PSI values.
//
// File format:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
func readMemoryPSI(cgPath string) (some, full float64) {
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgPath, "memory.pressure"))
	if err != nil {
		return 0, 0
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0] // "some" or "full"
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "avg10=") {
				val, err := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
				if err != nil {
					break
				}
				switch kind {
				case "some":
					some = val
				case "full":
					full = val
				}
				break
			}
		}
	}
	return some, full
}

// scanCgroupProcs returns all PIDs in a cgroup by reading
// /sys/fs/cgroup/<cgPath>/cgroup.procs.
func scanCgroupProcs(cgPath string) []uint32 {
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgPath, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(pid))
	}
	return pids
}

// readProcMemStats sums VIRT, PSS, and Shared bytes across all PIDs in a cgroup.
//
//   - VirtBytes  : sum of VmSize (kB) from /proc/<pid>/status → bytes
//   - PSSBytes   : sum of Pss from /proc/<pid>/smaps_rollup → bytes
//   - SharedBytes: sum of Shared_Clean + Shared_Dirty from smaps_rollup → bytes
//
// Reads are best-effort; PIDs that exit mid-scan are silently skipped.
func readProcMemStats(cgPath string) (virt, pss, shared uint64) {
	pids := scanCgroupProcs(cgPath)
	for _, pid := range pids {
		pidStr := strconv.FormatUint(uint64(pid), 10)

		// VmSize from /proc/<pid>/status
		if v, ok := readProcStatusField(pidStr, "VmSize:"); ok {
			virt += v * 1024 // kB → bytes
		}

		// PSS + Shared from /proc/<pid>/smaps_rollup
		p, s := readSmapsRollup(pidStr)
		pss += p
		shared += s
	}
	return virt, pss, shared
}

// readProcStatusField reads a single kB-valued field from /proc/<pid>/status.
// Returns (value_in_kB, true) on success, (0, false) on any error.
func readProcStatusField(pid, field string) (uint64, bool) {
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0, false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, field) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return v, true
				}
			}
		}
	}
	return 0, false
}

// readSmapsRollup reads /proc/<pid>/smaps_rollup and returns
// (pss_bytes, shared_bytes). Returns (0, 0) on any error.
func readSmapsRollup(pid string) (pss, shared uint64) {
	data, err := os.ReadFile("/proc/" + pid + "/smaps_rollup")
	if err != nil {
		return 0, 0
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "Pss:":
			pss += val * 1024 // kB → bytes
		case "Shared_Clean:":
			shared += val * 1024
		case "Shared_Dirty:":
			shared += val * 1024
		}
	}
	return pss, shared
}

func saturatingSubU64(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
