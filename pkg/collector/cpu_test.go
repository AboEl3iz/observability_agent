package collector

import "testing"

func TestSaturatingSub(t *testing.T) {
	tests := []struct {
		a, b uint64
		want uint64
	}{
		{100, 50, 50},
		{50, 100, 0},  // wrap-around guard
		{0, 0, 0},
		{1<<63 - 1, 0, 1<<63 - 1},
	}
	for _, tc := range tests {
		got := saturatingSub(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("saturatingSub(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCpuSampleRateComputation(t *testing.T) {
	// Verifies that the rate computation in Collect() is consistent with
	// the saturatingSub helper. We test the math in isolation since wiring
	// to a live BPF map requires root + kernel support.

	prevNs := uint64(1_000_000_000) // 1 billion ns = 1 s previously
	currNs := uint64(3_000_000_000) // 3 billion ns = 3 s now

	delta := saturatingSub(currNs, prevNs)
	cpuSeconds := float64(delta) / 1e9
	if cpuSeconds != 2.0 {
		t.Errorf("expected 2.0 CPU seconds, got %f", cpuSeconds)
	}
}
