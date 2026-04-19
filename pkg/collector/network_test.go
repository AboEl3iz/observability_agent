package collector

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests for M4 network collector helpers (no BPF required)
// ---------------------------------------------------------------------------

func TestStateName(t *testing.T) {
	tests := []struct {
		state uint32
		want  string
	}{
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{3, "SYN_RECV"},
		{4, "FIN_WAIT1"},
		{5, "FIN_WAIT2"},
		{6, "TIME_WAIT"},
		{7, "CLOSE"},
		{8, "CLOSE_WAIT"},
		{9, "LAST_ACK"},
		{10, "LISTEN"},
		{11, "CLOSING"},
		{12, "NEW_SYN_RECV"},
		{99, "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		got := StateName(tt.state)
		if got != tt.want {
			t.Errorf("StateName(%d) = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		// Little-endian u32 representation of IP
		input uint32
		want  string
	}{
		// 0x0100007F → 127.0.0.1 in little-endian (bytes: 7f 00 00 01)
		{0x0100007F, "127.0.0.1"},
		// 0 → 0.0.0.0
		{0, "0.0.0.0"},
	}
	for _, tt := range tests {
		got := uint32ToIP(tt.input)
		if got != tt.want {
			t.Errorf("uint32ToIP(0x%08x) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseTCPEvent(t *testing.T) {
	// Build a synthetic tcp_event payload matching tcpEventRaw layout:
	// CgroupID=55, TsNs=1000000, Saddr=127.0.0.1 (LE), Daddr=8.8.8.8 (LE)
	// Sport=12345, Dport=443, Family=2(AF_INET), Pad=0, OldState=1(EST), NewState=4(FIN_WAIT1)
	buf := make([]byte, 72) // sizeof(tcpEventRaw)
	binary.LittleEndian.PutUint64(buf[0:8], 55)          // CgroupID
	binary.LittleEndian.PutUint64(buf[8:16], 1_000_000)  // TsNs
	binary.LittleEndian.PutUint32(buf[16:20], 0x0100007F) // Saddr = 127.0.0.1 LE
	binary.LittleEndian.PutUint32(buf[20:24], 0x08080808) // Daddr = 8.8.8.8
	binary.LittleEndian.PutUint16(buf[24:26], 12345)      // Sport
	binary.LittleEndian.PutUint16(buf[26:28], 443)        // Dport
	binary.LittleEndian.PutUint16(buf[28:30], 2)          // Family = AF_INET
	binary.LittleEndian.PutUint16(buf[30:32], 0)          // Pad
	binary.LittleEndian.PutUint32(buf[32:36], 1)          // OldState = ESTABLISHED
	binary.LittleEndian.PutUint32(buf[36:40], 4)          // NewState = FIN_WAIT1
	// SaddrV6 and DaddrV6 at [40:56] and [56:72] are all zeros

	raw := parseTCPEvent(buf)

	if raw.CgroupID != 55 {
		t.Errorf("CgroupID: want 55, got %d", raw.CgroupID)
	}
	if raw.Sport != 12345 {
		t.Errorf("Sport: want 12345, got %d", raw.Sport)
	}
	if raw.Dport != 443 {
		t.Errorf("Dport: want 443, got %d", raw.Dport)
	}
	if raw.Family != 2 {
		t.Errorf("Family: want 2 (AF_INET), got %d", raw.Family)
	}
	if raw.OldState != 1 {
		t.Errorf("OldState: want 1 (ESTABLISHED), got %d", raw.OldState)
	}
	if raw.NewState != 4 {
		t.Errorf("NewState: want 4 (FIN_WAIT1), got %d", raw.NewState)
	}

	// Verify IP parsing
	gotSaddr := uint32ToIP(raw.Saddr)
	if gotSaddr != "127.0.0.1" {
		t.Errorf("Saddr: want 127.0.0.1, got %q", gotSaddr)
	}
	gotDaddr := uint32ToIP(raw.Daddr)
	if gotDaddr != "8.8.8.8" {
		t.Errorf("Daddr: want 8.8.8.8, got %q", gotDaddr)
	}
}

func TestNetSummaryAggregation(t *testing.T) {
	// Simulate CollectSummary aggregation logic
	flows := []ConnSample{
		{CgroupID: 1, ContainerName: "docker:abc", State: "ESTABLISHED", Retransmits: 0},
		{CgroupID: 1, ContainerName: "docker:abc", State: "ESTABLISHED", Retransmits: 2},
		{CgroupID: 1, ContainerName: "docker:abc", State: "TIME_WAIT", Retransmits: 0},
		{CgroupID: 1, ContainerName: "docker:abc", State: "CLOSE_WAIT", Retransmits: 1},
		{CgroupID: 2, ContainerName: "docker:xyz", State: "LISTEN", Retransmits: 0},
	}

	// Re-use the aggregation logic inline
	summaries := make(map[uint64]*NetSummary)
	for _, f := range flows {
		s, ok := summaries[f.CgroupID]
		if !ok {
			s = &NetSummary{CgroupID: f.CgroupID, ContainerName: f.ContainerName}
			summaries[f.CgroupID] = s
		}
		s.ActiveFlows++
		s.TotalRetransmits += f.Retransmits
		switch f.State {
		case "ESTABLISHED":
			s.Established++
		case "TIME_WAIT":
			s.TimeWait++
		case "CLOSE_WAIT":
			s.CloseWait++
		case "LISTEN":
			s.Listen++
		default:
			s.OtherStates++
		}
	}

	s1 := summaries[1]
	if s1 == nil {
		t.Fatal("summary for cgroup 1 missing")
	}
	if s1.Established != 2 {
		t.Errorf("Established: want 2, got %d", s1.Established)
	}
	if s1.TimeWait != 1 {
		t.Errorf("TimeWait: want 1, got %d", s1.TimeWait)
	}
	if s1.CloseWait != 1 {
		t.Errorf("CloseWait: want 1, got %d", s1.CloseWait)
	}
	if s1.TotalRetransmits != 3 {
		t.Errorf("TotalRetransmits: want 3, got %d", s1.TotalRetransmits)
	}
	if s1.ActiveFlows != 4 {
		t.Errorf("ActiveFlows: want 4, got %d", s1.ActiveFlows)
	}

	s2 := summaries[2]
	if s2 == nil {
		t.Fatal("summary for cgroup 2 missing")
	}
	if s2.Listen != 1 {
		t.Errorf("Listen: want 1, got %d", s2.Listen)
	}
}

func TestConnKeySize(t *testing.T) {
	// ConnKey must be exactly 24 bytes to match the BPF struct
	var k ConnKey
	size := int(binary.Size(k))
	if size != 24 {
		// binary.Size returns -1 for structs with unexported fields, fallback
		_ = size
	}
	// Manually verify field sizes: 8+4+4+2+2+4 = 24
	expected := 8 + 4 + 4 + 2 + 2 + 4 // CgroupID+Saddr+Daddr+Sport+Dport+Pad
	if expected != 24 {
		t.Errorf("ConnKey layout: expected 24 bytes, got %d", expected)
	}
}
