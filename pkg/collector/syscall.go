package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"sort"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
)

type SyscallStats struct {
	Count          uint64
	Failures       uint64
	TotalLatencyNs uint64
}

type SyscallSummary struct {
	ContainerName string
	SyscallID     uint32
	SyscallName   string
	Count         uint64
	Failures      uint64
	AvgLatencyMs  float64
	Rank          int // 1-based rank within the container (top-N most frequent)
}

type SyscallKey struct {
	CgroupID  uint64
	SyscallID uint32
	Pad       uint32
}

type slowSyscallEventRaw struct {
	CgroupID  uint64
	PID       uint32
	SyscallID uint32
	LatencyNs uint64
	Comm      [16]byte
}

type SlowSyscallSummary struct {
	ContainerName string
	PID           uint32
	SyscallID     uint32
	SyscallName   string
	LatencyMs     float64
	Comm          string
}

type SyscallCollector struct {
	statsMap *ebpf.Map
	rbReader *ringbuf.Reader
	resolver *cgroup.Resolver
	log      *slog.Logger
}

func NewSyscallCollector(statsMap, rbMap *ebpf.Map, resolver *cgroup.Resolver, log *slog.Logger) (*SyscallCollector, error) {
	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return nil, fmt.Errorf("opening slow_syscall_rb ring buffer: %w", err)
	}
	return &SyscallCollector{
		statsMap: statsMap,
		rbReader: rd,
		resolver: resolver,
		log:      log,
	}, nil
}

func (c *SyscallCollector) Collect() ([]SyscallSummary, error) {
	var summaries []SyscallSummary
	var key SyscallKey
	var stats SyscallStats

	var toDelete []SyscallKey
	iter := c.statsMap.Iterate()
	for iter.Next(&key, &stats) {
		name := fmt.Sprintf("cgroup:%d", key.CgroupID)
		info, ok := c.resolver.Lookup(key.CgroupID)
		if ok {
			name = info.Name
		} else {
			// Dead container and history expired -> evict from BPF map to save kernel memory
			toDelete = append(toDelete, key)
			continue
		}

		avgLat := 0.0
		if stats.Count > 0 {
			avgLat = float64(stats.TotalLatencyNs) / float64(stats.Count) / 1000000.0
		}
		summaries = append(summaries, SyscallSummary{
			ContainerName: name,
			SyscallID:     key.SyscallID,
			SyscallName:   SyscallName(key.SyscallID),
			Count:         stats.Count,
			Failures:      stats.Failures,
			AvgLatencyMs:  avgLat,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	for _, k := range toDelete {
		_ = c.statsMap.Delete(&k)
	}

	return summaries, nil
}

// CollectTop5PerContainer returns, for each container, only the top 5 most
// frequently called syscalls (sorted by Count descending, ranked 1–5).
// This keeps the display focused and prevents flooding the UI with hundreds
// of low-frequency syscall entries.
func (c *SyscallCollector) CollectTop5PerContainer() ([]SyscallSummary, error) {
	all, err := c.Collect()
	if err != nil {
		return nil, err
	}

	// Group by container name.
	byContainer := make(map[string][]SyscallSummary)
	for _, s := range all {
		byContainer[s.ContainerName] = append(byContainer[s.ContainerName], s)
	}

	const topN = 5
	var result []SyscallSummary
	for _, entries := range byContainer {
		// Sort this container's syscalls by count descending.
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Count > entries[j].Count
		})
		if len(entries) > topN {
			entries = entries[:topN]
		}
		// Stamp rank within the container.
		for i := range entries {
			entries[i].Rank = i + 1
		}
		result = append(result, entries...)
	}

	// Final sort: container name asc, then rank asc — stable display order.
	sort.Slice(result, func(i, j int) bool {
		if result[i].ContainerName != result[j].ContainerName {
			return result[i].ContainerName < result[j].ContainerName
		}
		return result[i].Rank < result[j].Rank
	})

	return result, nil
}

func (c *SyscallCollector) ReadSlowEvents() ([]SlowSyscallSummary, error) {
	var events []SlowSyscallSummary
	const rawSize = int(unsafe.Sizeof(slowSyscallEventRaw{}))

	for {
		c.rbReader.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.rbReader.Read()
		if err != nil {
			break
		}

		if len(rec.RawSample) < rawSize {
			c.log.Warn("short slow syscall ring buffer record", "len", len(rec.RawSample))
			continue
		}

		var raw slowSyscallEventRaw
		raw.CgroupID = binary.LittleEndian.Uint64(rec.RawSample[0:8])
		raw.PID = binary.LittleEndian.Uint32(rec.RawSample[8:12])
		raw.SyscallID = binary.LittleEndian.Uint32(rec.RawSample[12:16])
		raw.LatencyNs = binary.LittleEndian.Uint64(rec.RawSample[16:24])
		copy(raw.Comm[:], rec.RawSample[24:40])

		name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
		if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
			name = info.Name
		}

		events = append(events, SlowSyscallSummary{
			ContainerName: name,
			PID:           raw.PID,
			SyscallID:     raw.SyscallID,
			SyscallName:   SyscallName(raw.SyscallID),
			LatencyMs:     float64(raw.LatencyNs) / 1000000.0,
			Comm:          commString(raw.Comm[:]),
		})
	}
	return events, nil
}

func (c *SyscallCollector) Close() {
	if c.rbReader != nil {
		c.rbReader.Close()
	}
}
