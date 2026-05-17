package percentile

import (
	"sync"
	"testing"
)

func TestLatencyAggregator_Basic(t *testing.T) {
	agg := NewLatencyAggregator()

	// Record some values
	agg.Record("test_key", 100) // 100us = 0.1ms
	agg.Record("test_key", 200) // 200us = 0.2ms
	agg.Record("test_key", 500) // 500us = 0.5ms

	// Tick to update snapshots
	agg.Tick()

	snaps := agg.Snapshot()
	ws, ok := snaps["test_key"]
	if !ok {
		t.Fatal("expected test_key in snapshot")
	}

	if ws.W10s.Max < 0.49 || ws.W10s.Max > 0.51 {
		t.Errorf("expected max ~0.5, got %v", ws.W10s.Max)
	}
	if ws.W10s.P50 < 0.19 || ws.W10s.P50 > 0.21 {
		t.Errorf("expected p50 ~0.2, got %v", ws.W10s.P50)
	}

	// Test tumbling reset at 10 ticks
	for i := 0; i < 9; i++ {
		agg.Tick()
	}
	
	// Right after the 10th tick, W10s should be cleared.
	// We'll record a new value first to see if it starts fresh on tick 11
	agg.Record("test_key", 900)
	agg.Tick() // Tick 11
	
	snaps2 := agg.Snapshot()
	ws2 := snaps2["test_key"]
	if ws2.W10s.Max < 0.89 || ws2.W10s.Max > 0.91 {
		t.Errorf("expected W10s max ~0.9, got %v", ws2.W10s.Max)
	}
	// W60s wasn't cleared, so its max should still be ~0.9 (since 900 > 500)
	if ws2.W60s.Max < 0.89 || ws2.W60s.Max > 0.91 {
		t.Errorf("expected W60s max ~0.9, got %v", ws2.W60s.Max)
	}
}

func TestLatencyAggregator_Race(t *testing.T) {
	agg := NewLatencyAggregator()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			agg.Record("key1", int64(i+1))
			agg.Record("key2", int64(i+1))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			agg.Tick()
			_ = agg.Snapshot()
		}
	}()

	wg.Wait()
}
