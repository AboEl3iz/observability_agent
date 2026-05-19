// Package collector — M4: Network Connection Tracking
//
// The NetworkCollector does two things:
//
//  1. Polls the BPF hash map `conn_stats_map` every interval to produce
//     per-container TCP connection gauges and retransmit counters.
//
//  2. Drains the BPF ring buffer `tcp_event_rb` to stream individual
//     TCP state transitions (connect, close, time_wait, etc.) in real time.
//
// Metrics produced:
//
//	container_tcp_connections{state="ESTABLISHED|TIME_WAIT|..."}  – gauge
//	container_tcp_retransmits_total                               – counter
//	container_tcp_active_flows                                    – gauge (distinct flows)
package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
)

// ---------------------------------------------------------------------------
// TCP state names
// ---------------------------------------------------------------------------

var tcpStateNames = map[uint32]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

// StateName returns the TCP state string for a numeric state value.
func StateName(state uint32) string {
	if s, ok := tcpStateNames[state]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

// ---------------------------------------------------------------------------
// BPF map mirror types
// ---------------------------------------------------------------------------

// ConnKey mirrors struct conn_key from network.c (must match exactly).
// Total size: 8+4+4+2+2+4 = 24 bytes.
type ConnKey struct {
	CgroupID uint64
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Pad      uint32
}

// ConnStats mirrors struct conn_stats from network.c.
type ConnStats struct {
	State       uint32
	Retransmits uint32
	FirstSeenNs uint64
	LastSeenNs  uint64
}

// tcpEventRaw is the on-wire layout of struct tcp_event from network.c.
type tcpEventRaw struct {
	CgroupID uint64
	TsNs     uint64
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Family   uint16
	Pad      uint16
	OldState int32
	NewState int32
	SaddrV6  [16]byte
	DaddrV6  [16]byte
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// ConnSample represents a single active TCP flow at collection time.
type ConnSample struct {
	CgroupID      uint64
	ContainerName string
	Saddr         string // dotted-decimal IPv4
	Daddr         string
	Sport         uint16
	Dport         uint16
	State         string
	Retransmits   uint32
	AgeSeconds    float64 // how long the flow has been tracked
}

// NetSummary is the per-container aggregate view.
type NetSummary struct {
	CgroupID      uint64
	ContainerName string
	// State distribution
	Established  int
	TimeWait     int
	CloseWait    int
	Listen       int
	OtherStates  int
	ActiveFlows  int
	// Retransmit totals
	TotalRetransmits uint32
}

// TCPEvent represents a single TCP state transition from the ring buffer.
type TCPEvent struct {
	Timestamp     time.Time
	CgroupID      uint64
	ContainerName string
	Saddr         string
	Daddr         string
	Sport         uint16
	Dport         uint16
	Family        uint16
	OldState      string
	NewState      string
}

// NetworkCollector polls the conn_stats_map and streams TCP events.
type NetworkCollector struct {
	connMap  *ebpf.Map
	tcpRB    *ringbuf.Reader
	resolver *cgroup.Resolver
	log      *slog.Logger
}

// NewNetworkCollector creates a NetworkCollector.
//   - connMap : BPF map "conn_stats_map"
//   - tcpRBMap: BPF map "tcp_event_rb" (ring buffer)
func NewNetworkCollector(connMap *ebpf.Map, tcpRBMap *ebpf.Map, resolver *cgroup.Resolver, log *slog.Logger) (*NetworkCollector, error) {
	rd, err := ringbuf.NewReader(tcpRBMap)
	if err != nil {
		return nil, fmt.Errorf("opening tcp_event_rb ring buffer: %w", err)
	}
	return &NetworkCollector{
		connMap:  connMap,
		tcpRB:    rd,
		resolver: resolver,
		log:      log,
	}, nil
}

// Close releases the ring buffer reader.
func (n *NetworkCollector) Close() {
	if n.tcpRB != nil {
		n.tcpRB.Close()
	}
}

// CollectFlows returns all active TCP flows, resolved to container names.
func (n *NetworkCollector) CollectFlows() ([]ConnSample, error) {
	now := time.Now()
	var flows []ConnSample

	var key ConnKey
	var val ConnStats

	var toDelete []ConnKey
	iter := n.connMap.Iterate()
	for iter.Next(&key, &val) {
		name := fmt.Sprintf("cgroup:%d", key.CgroupID)
		info, ok := n.resolver.Lookup(key.CgroupID)
		if ok {
			name = info.Name
		} else {
			// Dead container and history expired -> evict from BPF map to save kernel memory
			toDelete = append(toDelete, key)
			continue
		}

		var ageSec float64
		if val.FirstSeenNs > 0 {
			ageSec = float64(now.UnixNano()-int64(val.FirstSeenNs)) / 1e9
		}

		flows = append(flows, ConnSample{
			CgroupID:      key.CgroupID,
			ContainerName: name,
			Saddr:         uint32ToIP(key.Saddr),
			Daddr:         uint32ToIP(key.Daddr),
			Sport:         key.Sport,
			Dport:         key.Dport,
			State:         StateName(val.State),
			Retransmits:   val.Retransmits,
			AgeSeconds:    ageSec,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating conn_stats_map: %w", err)
	}

	for _, k := range toDelete {
		_ = n.connMap.Delete(&k)
	}
	return flows, nil
}

// CollectSummary aggregates conn_stats_map into per-container summaries.
func (n *NetworkCollector) CollectSummary() ([]NetSummary, error) {
	flows, err := n.CollectFlows()
	if err != nil {
		return nil, err
	}

	summaries := make(map[uint64]*NetSummary)
	for _, f := range flows {
		s, ok := summaries[f.CgroupID]
		if !ok {
			s = &NetSummary{
				CgroupID:      f.CgroupID,
				ContainerName: f.ContainerName,
			}
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

	result := make([]NetSummary, 0, len(summaries))
	for _, s := range summaries {
		result = append(result, *s)
	}
	return result, nil
}

// ReadTCPEvents drains all pending TCP state transition events.
func (n *NetworkCollector) ReadTCPEvents() ([]TCPEvent, error) {
	var events []TCPEvent
	rawSize := int(unsafe.Sizeof(tcpEventRaw{}))

	for {
		n.tcpRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := n.tcpRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			n.log.Warn("short tcp_event record", "len", len(rec.RawSample))
			continue
		}

		raw := parseTCPEvent(rec.RawSample)
		name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
		if info, ok := n.resolver.Lookup(raw.CgroupID); ok {
			name = info.Name
		}

		events = append(events, TCPEvent{
			Timestamp:     time.Now(),
			CgroupID:      raw.CgroupID,
			ContainerName: name,
			Saddr:         uint32ToIP(raw.Saddr),
			Daddr:         uint32ToIP(raw.Daddr),
			Sport:         raw.Sport,
			Dport:         raw.Dport,
			Family:        raw.Family,
			OldState:      StateName(uint32(raw.OldState)),
			NewState:      StateName(uint32(raw.NewState)),
		})
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func parseTCPEvent(data []byte) tcpEventRaw {
	var r tcpEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.TsNs = binary.LittleEndian.Uint64(data[8:16])
	r.Saddr = binary.LittleEndian.Uint32(data[16:20])
	r.Daddr = binary.LittleEndian.Uint32(data[20:24])
	r.Sport = binary.LittleEndian.Uint16(data[24:26])
	r.Dport = binary.LittleEndian.Uint16(data[26:28])
	r.Family = binary.LittleEndian.Uint16(data[28:30])
	r.Pad = binary.LittleEndian.Uint16(data[30:32])
	r.OldState = int32(binary.LittleEndian.Uint32(data[32:36]))
	r.NewState = int32(binary.LittleEndian.Uint32(data[36:40]))
	copy(r.SaddrV6[:], data[40:56])
	copy(r.DaddrV6[:], data[56:72])
	return r
}

func uint32ToIP(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b).String()
}
