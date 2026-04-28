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

	iter := c.statsMap.Iterate()
	for iter.Next(&key, &stats) {
		name := fmt.Sprintf("cgroup:%d", key.CgroupID)
		if info, ok := c.resolver.Lookup(key.CgroupID); ok {
			name = info.Name
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

	return summaries, nil
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
