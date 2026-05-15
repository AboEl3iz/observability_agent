// Package collector — Phase 5: Container Escape Indicators
//
// EscapeCollector reads escape_events ring buffer and emits enriched
// EventEnvelopes for mount, unshare, and pivot_root syscall events.
//
// False positive handling for pivot_root:
//   Known container runtime process names (containerd-shim, runc, dockerd, crio)
//   are flagged as "runtime_initiated" in event metadata. Go consumers can use
//   this to suppress alerts for legitimate runtime operations at container startup.
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

// Indicator type constants — match #defines in escape.c
const (
	indMount      = 1
	indUnshare    = 2
	indPivotRoot  = 3
)

// Namespace flag names (linux/sched.h)
var nsFlagNames = map[uint32]string{
	0x00020000: "CLONE_NEWNS",
	0x04000000: "CLONE_NEWUTS",
	0x08000000: "CLONE_NEWIPC",
	0x10000000: "CLONE_NEWUSER",
	0x20000000: "CLONE_NEWPID",
	0x40000000: "CLONE_NEWNET",
}

// Mount flag names (linux/fs.h)
var mountFlagNames = map[uint32]string{
	0x00000001: "MS_RDONLY",
	0x00000002: "MS_NOSUID",
	0x00000004: "MS_NODEV",
	0x00000008: "MS_NOEXEC",
	0x00000010: "MS_SYNCHRONOUS",
	0x00000020: "MS_REMOUNT",
	0x00000040: "MS_MANDLOCK",
	0x00000080: "MS_DIRSYNC",
	0x00000400: "MS_NOATIME",
	0x00000800: "MS_NODIRATIME",
	0x00001000: "MS_BIND",
	0x00002000: "MS_MOVE",
	0x00004000: "MS_REC",
}

// knownRuntimes: process names that legitimately call pivot_root and unshare.
// Events from these processes are flagged "runtime_initiated=true" (not suppressed).
var knownRuntimes = map[string]bool{
	"containerd-shim":    true,
	"containerd-shim-runc-v2": true,
	"runc":              true,
	"dockerd":           true,
	"crio":              true,
	"crun":              true,
	"podman":            true,
}

// escapeEventRaw mirrors struct escape_event from escape.c.
type escapeEventRaw struct {
	CgroupID      uint64
	TsNs          uint64
	TGID          uint32
	PPID          uint32
	Comm          [16]byte
	ParentComm    [16]byte
	IndicatorType uint32
	NsFlags       uint32
	Pad           [8]byte
}

// EscapeCollector drains escape_events ring buffer.
type EscapeCollector struct {
	escapeRB   *ringbuf.Reader
	lineage    lineage.LineageLookup
	resolver   *cgroup.Resolver
	writer     event.SecurityEventWriter
	bootOffset int64
	log        *slog.Logger
}

// NewEscapeCollector creates an EscapeCollector.
func NewEscapeCollector(
	escapeRBMap *ebpf.Map,
	lookup lineage.LineageLookup,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*EscapeCollector, error) {
	rd, err := ringbuf.NewReader(escapeRBMap)
	if err != nil {
		return nil, fmt.Errorf("opening escape_events ring buffer: %w", err)
	}
	return &EscapeCollector{
		escapeRB:   rd,
		lineage:    lookup,
		resolver:   resolver,
		writer:     writer,
		bootOffset: bootOffset,
		log:        log,
	}, nil
}

// Close releases resources.
func (c *EscapeCollector) Close() {
	if c.escapeRB != nil {
		c.escapeRB.Close()
	}
}

// ReadEscapeEvents drains all pending container escape indicator events.
func (c *EscapeCollector) ReadEscapeEvents() ([]event.EventEnvelope, error) {
	var events []event.EventEnvelope
	rawSize := int(unsafe.Sizeof(escapeEventRaw{}))

	for {
		c.escapeRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.escapeRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			c.log.Warn("short escape_events record", "len", len(rec.RawSample))
			continue
		}

		raw := parseEscapeEvent(rec.RawSample)
		env := c.escapeToEnvelope(&raw)
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

func decodeNsFlags(flags uint32, indType uint32) string {
	if flags == 0 {
		return ""
	}
	result := ""

	var flagMap map[uint32]string
	if indType == indMount {
		flagMap = mountFlagNames
	} else {
		flagMap = nsFlagNames
	}

	for flag, name := range flagMap {
		if flags&flag != 0 {
			if result != "" {
				result += "|"
			}
			result += name
		}
	}
	if result == "" {
		return fmt.Sprintf("0x%08x", flags)
	}
	return result
}

func indicatorTypeName(t uint32) string {
	switch t {
	case indMount:
		return "mount"
	case indUnshare:
		return "unshare"
	case indPivotRoot:
		return "pivot_root"
	default:
		return fmt.Sprintf("unknown_%d", t)
	}
}

func (c *EscapeCollector) escapeToEnvelope(raw *escapeEventRaw) event.EventEnvelope {
	ts := time.Unix(0, int64(raw.TsNs)+c.bootOffset).UTC()

	name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
	if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
		name = info.Name
	}

	process    := nullTermStr(raw.Comm[:])
	parentComm := nullTermStr(raw.ParentComm[:])

	parentProcess := parentComm
	ancestryTruncated := false

	if c.lineage != nil {
		ancestors, truncated := c.lineage.Ancestors(raw.CgroupID, raw.TGID, lineage.MaxAncestorDepth)
		ancestryTruncated = truncated
		if len(ancestors) > 0 {
			// Direct parent is last in the chain (chain is root-first)
			parentProcess = ancestors[len(ancestors)-1].Comm
		}
	}

	// Detect if this looks like a legitimate runtime operation
	runtimeInitiated := knownRuntimes[process] || knownRuntimes[parentComm]

	return event.EventEnvelope{
		Timestamp:         ts,
		CgroupID:          raw.CgroupID,
		ContainerName:     name,
		PID:               raw.TGID,
		PPID:              raw.PPID,
		Process:           process,
		ParentProcess:     parentProcess,
		EventType:         event.EventTypeEscapeIndicator,
		AncestryTruncated: ancestryTruncated,
		Metadata: map[string]any{
			"container":         name,
			"indicator_type":    indicatorTypeName(raw.IndicatorType),
			"namespace_flags":   decodeNsFlags(raw.NsFlags, raw.IndicatorType),
			"ns_flags_raw":      raw.NsFlags,
			"runtime_initiated": runtimeInitiated,
		},
	}
}

func parseEscapeEvent(data []byte) escapeEventRaw {
	var r escapeEventRaw
	r.CgroupID      = binary.LittleEndian.Uint64(data[0:8])
	r.TsNs          = binary.LittleEndian.Uint64(data[8:16])
	r.TGID          = binary.LittleEndian.Uint32(data[16:20])
	r.PPID          = binary.LittleEndian.Uint32(data[20:24])
	copy(r.Comm[:], data[24:40])
	copy(r.ParentComm[:], data[40:56])
	r.IndicatorType = binary.LittleEndian.Uint32(data[56:60])
	r.NsFlags       = binary.LittleEndian.Uint32(data[60:64])
	return r
}
