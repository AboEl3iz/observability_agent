package collector

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests for M3 I/O collector helpers (no BPF required)
// ---------------------------------------------------------------------------

func TestParseFileEvent(t *testing.T) {
	// Construct a raw file_event payload:
	// CgroupID=77, PID=1001, Flags=0 (O_RDONLY), Comm="cat", Filename="/etc/passwd"
	buf := make([]byte, 160) // 8+4+4+16+128
	binary.LittleEndian.PutUint64(buf[0:8], 77)
	binary.LittleEndian.PutUint32(buf[8:12], 1001)
	binary.LittleEndian.PutUint32(buf[12:16], 0) // O_RDONLY
	copy(buf[16:32], "cat\x00")
	copy(buf[32:160], "/etc/passwd\x00")

	raw := parseFileEvent(buf)

	if raw.CgroupID != 77 {
		t.Errorf("CgroupID: want 77, got %d", raw.CgroupID)
	}
	if raw.PID != 1001 {
		t.Errorf("PID: want 1001, got %d", raw.PID)
	}
	if raw.Flags != 0 {
		t.Errorf("Flags: want 0, got %d", raw.Flags)
	}
	if comm := nullTermStr(raw.Comm[:]); comm != "cat" {
		t.Errorf("Comm: want \"cat\", got %q", comm)
	}
	if fn := nullTermStr(raw.Filename[:]); fn != "/etc/passwd" {
		t.Errorf("Filename: want \"/etc/passwd\", got %q", fn)
	}
}

func TestNullTermStr(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"normal", []byte("hello\x00world"), "hello"},
		{"no null", []byte("abcde"), "abcde"},
		{"empty", []byte{0, 1, 2}, ""},
		{"all null", []byte{0, 0, 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nullTermStr(tt.in)
			if got != tt.want {
				t.Errorf("nullTermStr(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIoSampleRateComputation(t *testing.T) {
	// Simulate two snapshots 2s apart and verify rate derivation
	prev := IoStats{
		ReadBytes:  1_000_000,
		WriteBytes: 500_000,
		ReadIOs:    100,
		WriteIOs:   50,
	}
	curr := IoStats{
		ReadBytes:  1_100_000, // +100KB
		WriteBytes: 600_000,   // +100KB
		ReadIOs:    110,       // +10 IOs
		WriteIOs:   60,        // +10 IOs
	}

	elapsed := 2.0 // seconds

	deltaRB := saturatingSubU64(curr.ReadBytes, prev.ReadBytes)
	deltaWB := saturatingSubU64(curr.WriteBytes, prev.WriteBytes)
	deltaRI := saturatingSubU64(curr.ReadIOs, prev.ReadIOs)
	deltaWI := saturatingSubU64(curr.WriteIOs, prev.WriteIOs)

	readBps := float64(deltaRB) / elapsed
	writeBps := float64(deltaWB) / elapsed
	readIops := float64(deltaRI) / elapsed
	writeIops := float64(deltaWI) / elapsed

	const tolerance = 0.001

	if diff := readBps - 50_000.0; diff > tolerance || diff < -tolerance {
		t.Errorf("ReadBytesPerSec: want 50000, got %.2f", readBps)
	}
	if diff := writeBps - 50_000.0; diff > tolerance || diff < -tolerance {
		t.Errorf("WriteBytesPerSec: want 50000, got %.2f", writeBps)
	}
	if diff := readIops - 5.0; diff > tolerance || diff < -tolerance {
		t.Errorf("ReadIOsPerSec: want 5, got %.2f", readIops)
	}
	if diff := writeIops - 5.0; diff > tolerance || diff < -tolerance {
		t.Errorf("WriteIOsPerSec: want 5, got %.2f", writeIops)
	}
}

func TestIoStatsLatencyAverage(t *testing.T) {
	// 10 reads, cumulative latency = 100ms (100_000_000 ns)
	deltaRI := uint64(10)
	deltaRL := uint64(100_000_000) // 100ms total

	avgMs := float64(deltaRL) / float64(deltaRI) / 1e6
	want := 10.0 // ms
	if diff := avgMs - want; diff > 0.001 || diff < -0.001 {
		t.Errorf("AvgReadLatencyMs: want %.2f, got %.2f", want, avgMs)
	}
}

// Helper used by memory_test.go too
func putU64(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

func putU32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}
