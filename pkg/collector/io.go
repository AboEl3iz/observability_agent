// Package collector — M3: Disk I/O & File System Access
//
// The IoCollector does two things:
//
//  1. Polls the BPF hash map `io_stats_map` every interval to produce
//     per-container block I/O throughput and latency metrics.
//
//  2. Reads the BPF ring buffer `file_events` to capture file open events,
//     useful for diagnosing database I/O patterns (WAL writes, InnoDB reads).
//
// Metrics produced:
//
//	container_io_read_bytes_total        – cumulative read bytes per container
//	container_io_write_bytes_total       – cumulative write bytes per container
//	container_io_read_ops_total          – cumulative read I/O ops
//	container_io_write_ops_total         – cumulative write I/O ops
//	container_io_read_latency_seconds    – avg read latency this interval
//	container_io_write_latency_seconds   – avg write latency this interval
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

// ---------------------------------------------------------------------------
// BPF map mirror types
// ---------------------------------------------------------------------------

// IoStats mirrors struct io_stats from io.c.
type IoStats struct {
	ReadBytes       uint64
	WriteBytes      uint64
	ReadIOs         uint64
	WriteIOs        uint64
	ReadLatencyNs   uint64
	WriteLatencyNs  uint64
}

// fileEventRaw is the on-wire layout of struct file_event from io.c.
type fileEventRaw struct {
	CgroupID uint64
	PID      uint32
	Flags    uint32
	Comm     [16]byte
	Filename [128]byte
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// IoSample is a per-container I/O snapshot for one collection interval.
type IoSample struct {
	CgroupID      uint64
	ContainerName string

	// Absolute counters (from the map)
	ReadBytes      uint64
	WriteBytes     uint64
	ReadIOs        uint64
	WriteIOs       uint64

	// Derived rates (delta over the interval)
	ReadBytesPerSec  float64
	WriteBytesPerSec float64
	ReadIOsPerSec    float64
	WriteIOsPerSec   float64

	// Average latency this interval (0 if no I/O)
	AvgReadLatencyMs  float64
	AvgWriteLatencyMs float64

	CollectedAt time.Time
}

// FileEvent represents a single file open observed in the container.
type FileEvent struct {
	Timestamp     time.Time
	CgroupID      uint64
	ContainerName string
	PID           uint32
	Flags         uint32
	Comm          string
	Filename      string
}

// IoCollector polls BPF I/O maps and streams file open events.
type IoCollector struct {
	ioMap    *ebpf.Map
	fileRB   *ringbuf.Reader
	resolver *cgroup.Resolver
	log      *slog.Logger

	prev   map[uint64]IoStats
	prevAt time.Time
}

// NewIoCollector creates an IoCollector.
//   - ioMap    : BPF map "io_stats_map"
//   - fileMap  : BPF map "file_events" (ring buffer)
//   - resolver : cgroup resolver (M0)
func NewIoCollector(ioMap *ebpf.Map, fileMap *ebpf.Map, resolver *cgroup.Resolver, log *slog.Logger) (*IoCollector, error) {
	rd, err := ringbuf.NewReader(fileMap)
	if err != nil {
		return nil, fmt.Errorf("opening file_events ring buffer: %w", err)
	}
	return &IoCollector{
		ioMap:    ioMap,
		fileRB:   rd,
		resolver: resolver,
		log:      log,
		prev:     make(map[uint64]IoStats),
	}, nil
}

// Close releases the ring buffer reader.
func (c *IoCollector) Close() {
	if c.fileRB != nil {
		c.fileRB.Close()
	}
}

// Collect reads io_stats_map and returns per-container I/O samples.
func (c *IoCollector) Collect() ([]IoSample, error) {
	now := time.Now()
	elapsed := now.Sub(c.prevAt).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var samples []IoSample
	var cgroupID uint64
	var val IoStats

	iter := c.ioMap.Iterate()
	for iter.Next(&cgroupID, &val) {
		name := fmt.Sprintf("cgroup:%d", cgroupID)
		if info, ok := c.resolver.Lookup(cgroupID); ok {
			name = info.Name
		}

		sample := IoSample{
			CgroupID:      cgroupID,
			ContainerName: name,
			ReadBytes:     val.ReadBytes,
			WriteBytes:    val.WriteBytes,
			ReadIOs:       val.ReadIOs,
			WriteIOs:      val.WriteIOs,
			CollectedAt:   now,
		}

		if prev, ok := c.prev[cgroupID]; ok {
			deltaRB := saturatingSubU64(val.ReadBytes, prev.ReadBytes)
			deltaWB := saturatingSubU64(val.WriteBytes, prev.WriteBytes)
			deltaRI := saturatingSubU64(val.ReadIOs, prev.ReadIOs)
			deltaWI := saturatingSubU64(val.WriteIOs, prev.WriteIOs)
			deltaRL := saturatingSubU64(val.ReadLatencyNs, prev.ReadLatencyNs)
			deltaWL := saturatingSubU64(val.WriteLatencyNs, prev.WriteLatencyNs)

			sample.ReadBytesPerSec = float64(deltaRB) / elapsed
			sample.WriteBytesPerSec = float64(deltaWB) / elapsed
			sample.ReadIOsPerSec = float64(deltaRI) / elapsed
			sample.WriteIOsPerSec = float64(deltaWI) / elapsed

			// Average latency this interval
			if deltaRI > 0 {
				sample.AvgReadLatencyMs = float64(deltaRL) / float64(deltaRI) / 1e6
			}
			if deltaWI > 0 {
				sample.AvgWriteLatencyMs = float64(deltaWL) / float64(deltaWI) / 1e6
			}
		}

		samples = append(samples, sample)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating io_stats_map: %w", err)
	}

	// Update previous snapshot
	c.prev = make(map[uint64]IoStats, len(samples))
	for _, s := range samples {
		c.prev[s.CgroupID] = IoStats{
			ReadBytes:      s.ReadBytes,
			WriteBytes:     s.WriteBytes,
			ReadIOs:        s.ReadIOs,
			WriteIOs:       s.WriteIOs,
			ReadLatencyNs:  val.ReadLatencyNs,
			WriteLatencyNs: val.WriteLatencyNs,
		}
	}
	c.prevAt = now

	return samples, nil
}

// ReadFileEvents drains all pending file open events from the ring buffer.
func (c *IoCollector) ReadFileEvents() ([]FileEvent, error) {
	var events []FileEvent
	rawSize := int(unsafe.Sizeof(fileEventRaw{}))

	for {
		c.fileRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.fileRB.Read()
		if err != nil {
			break
		}

		if len(rec.RawSample) < rawSize {
			c.log.Warn("short file_event ring buffer record", "len", len(rec.RawSample))
			continue
		}

		raw := parseFileEvent(rec.RawSample)
		name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
		if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
			name = info.Name
		}

		events = append(events, FileEvent{
			Timestamp:     time.Now(),
			CgroupID:      raw.CgroupID,
			ContainerName: name,
			PID:           raw.PID,
			Flags:         raw.Flags,
			Comm:          nullTermStr(raw.Comm[:]),
			Filename:      nullTermStr(raw.Filename[:]),
		})
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func parseFileEvent(data []byte) fileEventRaw {
	var r fileEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.PID = binary.LittleEndian.Uint32(data[8:12])
	r.Flags = binary.LittleEndian.Uint32(data[12:16])
	copy(r.Comm[:], data[16:32])
	copy(r.Filename[:], data[32:160])
	return r
}

func nullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
