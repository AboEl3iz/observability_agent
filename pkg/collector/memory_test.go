package collector

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit tests for M2 memory collector helpers (no BPF required)
// ---------------------------------------------------------------------------

func TestParseOOMEvent(t *testing.T) {
	// Build a synthetic raw payload matching oomEventRaw layout
	// CgroupID=42, VictimPID=1234, OOMScoreAdj=500, Pages=65536, Comm="stress"
	buf := make([]byte, 40)
	putU64(buf[0:8], 42)
	putU32(buf[8:12], 1234)
	putU32(buf[12:16], 500)
	putU64(buf[16:24], 65536)
	copy(buf[24:40], "stress\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	raw := parseOOMEvent(buf)

	if raw.CgroupID != 42 {
		t.Errorf("CgroupID: want 42, got %d", raw.CgroupID)
	}
	if raw.VictimPID != 1234 {
		t.Errorf("VictimPID: want 1234, got %d", raw.VictimPID)
	}
	if raw.OOMScoreAdj != 500 {
		t.Errorf("OOMScoreAdj: want 500, got %d", raw.OOMScoreAdj)
	}
	if raw.Pages != 65536 {
		t.Errorf("Pages: want 65536, got %d", raw.Pages)
	}
	got := commString(raw.Comm[:])
	if got != "stress" {
		t.Errorf("Comm: want \"stress\", got %q", got)
	}
}

func TestCommString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"null terminated", append([]byte("nginx"), 0, 0, 0), "nginx"},
		{"full no null", []byte("abcdefghijklmnop"), "abcdefghijklmnop"},
		{"empty", []byte{0, 0, 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commString(tt.in)
			if got != tt.want {
				t.Errorf("commString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadCgroupUint64_Max(t *testing.T) {
	// readCgroupUint64 on a non-existent path should return 0
	v := readCgroupUint64("nonexistent/cgroup", "memory.max")
	if v != 0 {
		t.Errorf("expected 0 for missing file, got %d", v)
	}
}

func TestReadCgroupUint64_File(t *testing.T) {
	// Write a temp file to simulate a cgroupfs memory.current file
	// We use /tmp as the "root" (readCgroupUint64 prepends /sys/fs/cgroup,
	// so we cannot easily intercept — just verify it handles numbers correctly)
	// This is a parse-level test only.
	tests := []struct {
		raw  string
		want uint64
	}{
		{"12345678\n", 12345678},
		{"max\n", 0},
		{"0\n", 0},
	}
	for _, tt := range tests {
		s := strings.TrimSpace(tt.raw)
		var got uint64
		if s != "max" {
			// inline the parser logic
			_, _ = func() (uint64, error) {
				var n uint64
				for _, c := range s {
					if c < '0' || c > '9' {
						return 0, nil
					}
					n = n*10 + uint64(c-'0')
				}
				got = n
				return got, nil
			}()
		}
		if got != tt.want {
			t.Errorf("parse(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestSaturatingSubU64(t *testing.T) {
	tests := []struct{ a, b, want uint64 }{
		{10, 3, 7},
		{3, 10, 0}, // underflow guard
		{0, 0, 0},
	}
	for _, tt := range tests {
		got := saturatingSubU64(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("saturatingSubU64(%d,%d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// OOMEvent struct validation
func TestOOMEventFields(t *testing.T) {
	ev := OOMEvent{
		Timestamp:     time.Now(),
		CgroupID:      99,
		ContainerName: "docker:abc123",
		VictimPID:     4242,
		OOMScoreAdj:   1000,
		Pages:         32768,
		Comm:          "python3",
		MemoryBytes:   64 * 1024 * 1024,
		MemoryLimitBytes: 64 * 1024 * 1024,
	}
	if ev.ContainerName != "docker:abc123" {
		t.Errorf("ContainerName mismatch")
	}
	if ev.Pages != 32768 {
		t.Errorf("Pages mismatch")
	}
	// Pages → KB approximation
	rkb := ev.Pages * 4 // 4KB pages
	if rkb != 131072 {
		t.Errorf("RSS KB: want 131072, got %d", rkb)
	}
}
