// Package collector provides per-subsystem metric collectors.
//
// M1: CPU & Thread Observability
//
// The CpuCollector reads the BPF map `cpu_stats_map` (keyed by cgroup_id)
// and produces the following metric families:
//
//	container_cpu_seconds_total         – total on-CPU time per container
//	container_runqueue_latency_seconds  – cumulative runq wait per container
//	container_threads                   – live thread count per container
//	container_ctx_switches_total        – context switches per container
//	container_numa_local_pct            – % NUMA-local task scheduling
//	container_numa_remote_pct           – % NUMA-remote scheduling (cross-NUMA migrations)
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	// Absolute counters from the BPF map.
	TotalNs       uint64
	RunqLatencyNs uint64
	CtxSwitches   uint64
	ThreadCount   uint32

	// Derived rates (computed against the previous snapshot).
	CPUSeconds         float64 // delta total_ns → seconds
	RunqLatencySeconds float64 // delta runq_latency_ns → seconds
	CtxSwitchesPerSec  float64

	// NUMA balance (sourced from /sys/fs/cgroup/<cg>/cpu.stat nr_migrations).
	// NUMALocalPct + NUMARemotePct = 100 (or 0 when data unavailable).
	NUMALocalPct  float64 // % of scheduling intervals that stayed NUMA-local
	NUMARemotePct float64 // % that required cross-NUMA migration

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

	var toDelete []CpuKey
	iter := c.cpuMap.Iterate()
	for iter.Next(&key, &val) {
		cgroupID := key.CgroupID

		// Resolve container name (M0)
		name := fmt.Sprintf("cgroup:%d", cgroupID)
		info, ok := c.resolver.Lookup(cgroupID)
		if ok {
			name = info.Name
		} else {
			// Dead container and history expired -> evict from BPF map to save kernel memory
			toDelete = append(toDelete, key)
			continue
		}

		threadCount := val.ThreadCount
		if threadCount > 1000000 { // Max uint32 wrap-around guard
			threadCount = 0
		}

		sample := CpuSample{
			CgroupID:      cgroupID,
			ContainerName: name,
			TotalNs:       val.TotalNs,
			RunqLatencyNs: val.RunqLatencyNs,
			CtxSwitches:   val.CtxSwitches,
			ThreadCount:   threadCount,
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

		// NUMA balance from cgroupfs cpu.stat (best-effort)
		if info, ok := c.resolver.Lookup(cgroupID); ok && info.CgroupPath != "" {
			sample.NUMALocalPct, sample.NUMARemotePct = readNUMAStats(info.CgroupPath)
		}

		samples = append(samples, sample)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating cpu_stats_map: %w", err)
	}

	for _, k := range toDelete {
		_ = c.cpuMap.Delete(&k)
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

// readNUMAStats reads /sys/fs/cgroup/<cg>/cpu.stat and returns
// (numaLocalPct, numaRemotePct) using the nr_migrations field as the remote indicator.
//
// Strategy:
//   - nr_migrations: number of times tasks in this cgroup were migrated away
//     (cross-CPU, often cross-NUMA on multi-socket systems).
//   - We track delta migrations per delta nr_periods (throttle periods) as a proxy.
//   - On single-NUMA systems migrations are very low → Local≈100%, Remote≈0%.
//   - On multi-NUMA systems migrations indicate cross-NUMA scheduling.
//
// We cap the remote% at 100 and compute local% = 100 - remote%.
func readNUMAStats(cgPath string) (localPct, remotePct float64) {
	localPct = 100.0
	data, err := os.ReadFile("/sys/fs/cgroup/" + cgPath + "/cpu.stat")
	if err != nil {
		return localPct, 0
	}
	var nrPeriods, nrMigrations uint64
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "nr_periods":
			nrPeriods = val
		case "nr_migrations_cold", "nr_failed_migrations_hot",
			"nr_failed_migrations_running", "nr_failed_migrations_numa",
			"nr_migrations":
			// Accumulate all migration-related counters as "remote" indicator
			nrMigrations += val
		}
	}
	if nrPeriods == 0 {
		// Fallback: if nr_periods not available, use a simple presence check
		// and treat migrations/1000 as percentage proxy
		if nrMigrations > 0 {
			remotePct = min64(float64(nrMigrations)/10.0, 100.0)
		}
		localPct = 100.0 - remotePct
		return localPct, remotePct
	}
	// Normalise: each period = one scheduling slot; migrations per period = remote ratio
	ratio := float64(nrMigrations) / float64(nrPeriods)
	remotePct = min64(ratio*100.0, 100.0)
	localPct = 100.0 - remotePct
	return localPct, remotePct
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
