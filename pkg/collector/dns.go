// Package collector — Phase 3: DNS Observability
//
// DnsCollector reads dns_events ring buffer events, decodes DNS wire format
// for QNAME and QTYPE, applies lineage enrichment, and emits EventEnvelopes.
//
// Scope (per Q4 decision):
//   QNAME + QTYPE + latency_ms + RCODE — full answer section OUT OF SCOPE.
//
// DNS QTYPE names (RFC 1035 + extensions):
//   1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV,
//   255=ANY
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
	"ebpf/pkg/event"
	"ebpf/pkg/lineage"
)

// dnsEventRaw mirrors struct dns_event from dns.c.
type dnsEventRaw struct {
	CgroupID    uint64
	SendTsNs    uint64
	LatencyNs   uint64
	TGID        uint32
	PPID        uint32
	Comm        [16]byte
	QName       [256]byte // MAX_DNS_NAME+1
	QType       uint16
	RCode       uint16
	HasResponse uint8
	ViaConnect  uint8 // 1 = musl/busybox connect()+send() path
	Pad         [2]byte
}

// qtypeNames maps DNS QTYPE numbers to human-readable names.
var qtypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	255: "ANY",
}

// rcodeNames maps DNS RCODE values to human-readable names.
var rcodeNames = map[uint16]string{
	0:  "NOERROR",
	1:  "FORMERR",
	2:  "SERVFAIL",
	3:  "NXDOMAIN",
	4:  "NOTIMP",
	5:  "REFUSED",
}

func qtypeName(qt uint16) string {
	if s, ok := qtypeNames[qt]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qt)
}

func rcodeName(rc uint16) string {
	if s, ok := rcodeNames[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// resolverStyle identifies the DNS resolver syscall pattern for diagnostics.
// "connected" = musl/busybox: connect()+send() — addr=NULL path
// "sendto"    = glibc/getaddrinfo: sendto() with explicit destination address
func resolverStyle(viaConnect uint8) string {
	if viaConnect == 1 {
		return "connected" // musl, busybox nslookup, golang net
	}
	return "sendto" // glibc
}

// DnsCollector drains dns_events ring buffer and emits DNS query events.
type DnsCollector struct {
	dnsRB      *ringbuf.Reader
	lineage    lineage.LineageLookup
	resolver   *cgroup.Resolver
	writer     event.SecurityEventWriter
	bootOffset int64
	log        *slog.Logger
}

// NewDnsCollector creates a DnsCollector.
func NewDnsCollector(
	dnsRBMap *ebpf.Map,
	lookup lineage.LineageLookup,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*DnsCollector, error) {
	rd, err := ringbuf.NewReader(dnsRBMap)
	if err != nil {
		return nil, fmt.Errorf("opening dns_events ring buffer: %w", err)
	}
	return &DnsCollector{
		dnsRB:      rd,
		lineage:    lookup,
		resolver:   resolver,
		writer:     writer,
		bootOffset: bootOffset,
		log:        log,
	}, nil
}

// Close releases resources.
func (c *DnsCollector) Close() {
	if c.dnsRB != nil {
		c.dnsRB.Close()
	}
}

// ReadDNSEvents drains all pending DNS events.
func (c *DnsCollector) ReadDNSEvents() ([]event.EventEnvelope, error) {
	var events []event.EventEnvelope
	rawSize := int(unsafe.Sizeof(dnsEventRaw{}))

	for {
		c.dnsRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.dnsRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			c.log.Warn("short dns_events record", "len", len(rec.RawSample))
			continue
		}

		raw := parseDNSEvent(rec.RawSample)
		env := c.dnsEventToEnvelope(&raw)
		events = append(events, env)

		if c.writer != nil {
			c.writer.Write(env)
		}
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (c *DnsCollector) dnsEventToEnvelope(raw *dnsEventRaw) event.EventEnvelope {
	ts := time.Unix(0, int64(raw.SendTsNs)+c.bootOffset).UTC()

	name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
	if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
		name = info.Name
	}

	process := nullTermStr(raw.Comm[:])
	parentProcess := ""
	if c.lineage != nil {
		if entry, ok := c.lineage.Lookup(raw.CgroupID, raw.PPID); ok {
			parentProcess = entry.Comm
		}
	}

	qname     := nullTermStr(raw.QName[:])
	latencyMs := float64(raw.LatencyNs) / 1e6

	return event.EventEnvelope{
		Timestamp:     ts,
		CgroupID:      raw.CgroupID,
		ContainerName: name,
		PID:           raw.TGID,
		PPID:          raw.PPID,
		Process:       process,
		ParentProcess: parentProcess,
		EventType:     event.EventTypeDNSQuery,
		Metadata: map[string]any{
			"container":      name,
			"query":          qname,
			"query_type":     qtypeName(raw.QType),
			"qtype_num":      raw.QType,
			"rcode":          rcodeName(raw.RCode),
			"rcode_num":      raw.RCode,
			"latency_ms":     latencyMs,
			"has_response":   raw.HasResponse == 1,
			"via_connect":    raw.ViaConnect == 1,  // musl/busybox path
			"resolver_style": resolverStyle(raw.ViaConnect),
		},
	}
}

func parseDNSEvent(data []byte) dnsEventRaw {
	var r dnsEventRaw
	r.CgroupID  = binary.LittleEndian.Uint64(data[0:8])
	r.SendTsNs  = binary.LittleEndian.Uint64(data[8:16])
	r.LatencyNs = binary.LittleEndian.Uint64(data[16:24])
	r.TGID      = binary.LittleEndian.Uint32(data[24:28])
	r.PPID      = binary.LittleEndian.Uint32(data[28:32])
	copy(r.Comm[:], data[32:48])
	copy(r.QName[:], data[48:304])
	r.QType       = binary.LittleEndian.Uint16(data[304:306])
	r.RCode       = binary.LittleEndian.Uint16(data[306:308])
	r.HasResponse = data[308]
	r.ViaConnect  = data[309]
	return r
}
