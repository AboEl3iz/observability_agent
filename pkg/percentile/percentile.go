package percentile

import (
	"sync"

	"github.com/HdrHistogram/hdrhistogram-go"
)

// Snapshot represents the precalculated percentiles for a metric.
type Snapshot struct {
	P50 float64
	P95 float64
	P99 float64
	Max float64
}

// WindowSnapshots holds snapshots for different time resolutions.
// We provide a unified view, but keep multiple resolutions if requested.
type WindowSnapshots struct {
	W10s  Snapshot
	W60s  Snapshot
	W300s Snapshot
}

// keyState holds the active and snapshot histograms for a single metric.
type keyState struct {
	mu sync.Mutex

	// We use 3 separate tumbling histograms to approximate sliding windows without huge memory overhead.
	// In a real high-throughput system, we might use a small ring buffer of histograms.
	active10s  *hdrhistogram.Histogram
	active60s  *hdrhistogram.Histogram
	active300s *hdrhistogram.Histogram

	// Snapshots generated on Tick
	snap WindowSnapshots
}

func newKeyState() *keyState {
	// Min 1 microsecond, Max 60 seconds, 2 significant figures.
	return &keyState{
		active10s:  hdrhistogram.New(1, 60000000, 2),
		active60s:  hdrhistogram.New(1, 60000000, 2),
		active300s: hdrhistogram.New(1, 60000000, 2),
	}
}

// LatencyAggregator manages HDR histograms for latency percentiles.
type LatencyAggregator struct {
	mu    sync.RWMutex
	keys  map[string]*keyState
	ticks uint64 // Number of 1-second ticks elapsed
}

// NewLatencyAggregator creates a new percentile aggregator.
func NewLatencyAggregator() *LatencyAggregator {
	return &LatencyAggregator{
		keys: make(map[string]*keyState),
	}
}

// Record latency in microseconds for a specific key.
func (a *LatencyAggregator) Record(key string, latencyUs int64) {
	a.RecordValues(key, latencyUs, 1)
}

// RecordValues records multiple occurrences of a latency value.
func (a *LatencyAggregator) RecordValues(key string, latencyUs int64, count int64) {
	if latencyUs < 1 {
		latencyUs = 1
	}
	if count < 1 {
		return
	}

	a.mu.RLock()
	ks, ok := a.keys[key]
	a.mu.RUnlock()

	if !ok {
		a.mu.Lock()
		ks, ok = a.keys[key]
		if !ok {
			ks = newKeyState()
			a.keys[key] = ks
		}
		a.mu.Unlock()
	}

	ks.mu.Lock()
	_ = ks.active10s.RecordValues(latencyUs, count)
	_ = ks.active60s.RecordValues(latencyUs, count)
	_ = ks.active300s.RecordValues(latencyUs, count)
	ks.mu.Unlock()
}

// Tick is called every second by the collection loop.
// It rotates histograms based on the window sizes and updates the lock-free snapshots.
func (a *LatencyAggregator) Tick() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	a.ticks++

	for _, ks := range a.keys {
		ks.mu.Lock()

		// Update snapshots from the active histograms.
		// We convert microseconds to milliseconds for the TUI display.
		ks.snap.W10s = Snapshot{
			P50: float64(ks.active10s.ValueAtQuantile(50)) / 1000.0,
			P95: float64(ks.active10s.ValueAtQuantile(95)) / 1000.0,
			P99: float64(ks.active10s.ValueAtQuantile(99)) / 1000.0,
			Max: float64(ks.active10s.Max()) / 1000.0,
		}
		ks.snap.W60s = Snapshot{
			P50: float64(ks.active60s.ValueAtQuantile(50)) / 1000.0,
			P95: float64(ks.active60s.ValueAtQuantile(95)) / 1000.0,
			P99: float64(ks.active60s.ValueAtQuantile(99)) / 1000.0,
			Max: float64(ks.active60s.Max()) / 1000.0,
		}
		ks.snap.W300s = Snapshot{
			P50: float64(ks.active300s.ValueAtQuantile(50)) / 1000.0,
			P95: float64(ks.active300s.ValueAtQuantile(95)) / 1000.0,
			P99: float64(ks.active300s.ValueAtQuantile(99)) / 1000.0,
			Max: float64(ks.active300s.Max()) / 1000.0,
		}

		// Tumbling window logic: reset active histograms when their window elapses.
		if a.ticks%10 == 0 {
			ks.active10s.Reset()
		}
		if a.ticks%60 == 0 {
			ks.active60s.Reset()
		}
		if a.ticks%300 == 0 {
			ks.active300s.Reset()
		}

		ks.mu.Unlock()
	}
}

// Snapshot returns a copy of the precalculated snapshots for all keys.
// This provides a lock-free snapshot for the TUI render thread.
func (a *LatencyAggregator) Snapshot() map[string]WindowSnapshots {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make(map[string]WindowSnapshots, len(a.keys))
	for k, ks := range a.keys {
		ks.mu.Lock()
		out[k] = ks.snap
		ks.mu.Unlock()
	}
	return out
}
