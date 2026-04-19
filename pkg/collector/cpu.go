// Package collector provides per-subsystem metric collectors.
//
// M1: CPU & Thread Observability
//
// The CpuCollector reads the BPF map `cpu_stats_map` (keyed by cgroup_id)
// and produces three metric families:
//
//	container_cpu_seconds_total      – total on-CPU time per container
//	container_runqueue_latency_seconds – cumulative runq wait per container
//	container_threads                – live thread count per container
//	container_ctx_switches_total     – context switches per container
package collector

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"ebpf/pkg/cgroup"
)

// CpuKey mirrors the BPF struct cpu_key.
type CpuKey struct {
	CgroupID uint64
}

// CpuStats mirrors the BPF struct cpu_stats.
type CpuStats struct {
	TotalNs        uint64
	RunqLatencyNs  uint64
	CtxSwitches    uint64
	ThreadCount    uint32
	Pad            uint32
}

// CpuSample is a point-in-time snapshot for a single cgroup.
type CpuSample struct {
	CgroupID      uint64
	ContainerName string

	// Absolute counters from the map.
	TotalNs       uint64
	RunqLatencyNs uint64
	CtxSwitches   uint64
	ThreadCount   uint32

	// Derived rates (computed against the previous snapshot).
	CPUSeconds          float64 // delta total_ns → seconds
	RunqLatencySeconds  float64 // delta runq_latency_ns → seconds
	CtxSwitchesPerSec   float64

	CollectedAt time.Time
}

// CpuCollector polls the BPF cpu_stats_map and resolves container names.
type CpuCollector struct {
	cpuMap   *ebpf.Map
	resolver *cgroup.Resolver
	prev     map[uint64]CpuStats
	prevAt   time.Time
}

// NewCpuCollector constructs a CpuCollector.
// cpuMap must point to the BPF map named "cpu_stats_map".
func NewCpuCollector(cpuMap *ebpf.Map, resolver *cgroup.Resolver) *CpuCollector {
	return &CpuCollector{
		cpuMap:   cpuMap,
		resolver: resolver,
		prev:     make(map[uint64]CpuStats),
	}
}

// Collect reads the BPF map and returns per-container samples.
func (c *CpuCollector) Collect() ([]CpuSample, error) {
	now := time.Now()
	elapsed := now.Sub(c.prevAt).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var samples []CpuSample

	var key CpuKey
	var val CpuStats

	iter := c.cpuMap.Iterate()
	for iter.Next(&key, &val) {
		cgroupID := key.CgroupID

		// Resolve container name (M0)
		name := fmt.Sprintf("cgroup:%d", cgroupID)
		if info, ok := c.resolver.Lookup(cgroupID); ok {
			name = info.Name
		}

		sample := CpuSample{
			CgroupID:      cgroupID,
			ContainerName: name,
			TotalNs:       val.TotalNs,
			RunqLatencyNs: val.RunqLatencyNs,
			CtxSwitches:   val.CtxSwitches,
			ThreadCount:   val.ThreadCount,
			CollectedAt:   now,
		}

		// Compute deltas if we have a previous reading
		if prev, ok := c.prev[cgroupID]; ok {
			deltaNs := saturatingSub(val.TotalNs, prev.TotalNs)
			deltaRunq := saturatingSub(val.RunqLatencyNs, prev.RunqLatencyNs)
			deltaCtx := saturatingSub(val.CtxSwitches, prev.CtxSwitches)

			sample.CPUSeconds = float64(deltaNs) / 1e9
			sample.RunqLatencySeconds = float64(deltaRunq) / 1e9
			sample.CtxSwitchesPerSec = float64(deltaCtx) / elapsed
		}

		samples = append(samples, sample)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating cpu_stats_map: %w", err)
	}

	// Update previous snapshot
	c.prev = make(map[uint64]CpuStats, len(samples))
	for _, s := range samples {
		c.prev[s.CgroupID] = CpuStats{
			TotalNs:       s.TotalNs,
			RunqLatencyNs: s.RunqLatencyNs,
			CtxSwitches:   s.CtxSwitches,
			ThreadCount:   s.ThreadCount,
		}
	}
	c.prevAt = now

	return samples, nil
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0 // counter reset or wrap-around guard
	}
	return a - b
}
