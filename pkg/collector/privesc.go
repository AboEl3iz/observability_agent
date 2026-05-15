// Package collector — Phase 4: Privilege Escalation Detection
//
// PrivEscCollector reads privesc_events ring buffer and emits enriched
// EventEnvelopes for setuid, setgid, ptrace, and cap_capable events.
//
// cap_capable availability: the BPF program attaches cap_capable as a kprobe
// (best-effort). The CapKprobeAvailable field indicates if it loaded successfully.
// Downstream consumers can use this to know the detection coverage.
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

// Escalation type constants — match #defines in privesc.c
const (
	escTypeSetUID = 1
	escTypeSetGID = 2
	escTypePtrace = 3
	escTypeCap    = 4
)

// Capability names (linux/capability.h subset)
var capNames = map[uint32]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
}

var escTypeNames = map[uint32]string{
	escTypeSetUID: "setuid",
	escTypeSetGID: "setgid",
	escTypePtrace: "ptrace",
	escTypeCap:    "cap_capable",
}

// privescEventRaw mirrors struct privesc_event from privesc.c.
type privescEventRaw struct {
	CgroupID   uint64
	TsNs       uint64
	TGID       uint32
	PPID       uint32
	Comm       [16]byte
	ParentComm [16]byte
	OldUID     uint32
	NewUID     uint32
	EscType    uint32
	Cap        uint32
	PtracePID  uint32
	Pad        uint32
}

// PrivEscCollector drains privesc_events and emits enriched events.
type PrivEscCollector struct {
	privescRB         *ringbuf.Reader
	lineage           lineage.LineageLookup
	resolver          *cgroup.Resolver
	writer            event.SecurityEventWriter
	bootOffset        int64
	CapKprobeAvailable bool // set by loader after attach attempt
	log               *slog.Logger
}

// NewPrivEscCollector creates a PrivEscCollector.
func NewPrivEscCollector(
	privescRBMap *ebpf.Map,
	lookup lineage.LineageLookup,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*PrivEscCollector, error) {
	rd, err := ringbuf.NewReader(privescRBMap)
	if err != nil {
		return nil, fmt.Errorf("opening privesc_events ring buffer: %w", err)
	}
	return &PrivEscCollector{
		privescRB:  rd,
		lineage:    lookup,
		resolver:   resolver,
		writer:     writer,
		bootOffset: bootOffset,
		log:        log,
	}, nil
}

// Close releases resources.
func (c *PrivEscCollector) Close() {
	if c.privescRB != nil {
		c.privescRB.Close()
	}
}

// ReadPrivEscEvents drains all pending privilege escalation events.
func (c *PrivEscCollector) ReadPrivEscEvents() ([]event.EventEnvelope, error) {
	var events []event.EventEnvelope
	rawSize := int(unsafe.Sizeof(privescEventRaw{}))

	for {
		c.privescRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.privescRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			c.log.Warn("short privesc_events record", "len", len(rec.RawSample))
			continue
		}

		raw := parsePrivEscEvent(rec.RawSample)
		env := c.privEscToEnvelope(&raw)
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

func (c *PrivEscCollector) privEscToEnvelope(raw *privescEventRaw) event.EventEnvelope {
	ts := time.Unix(0, int64(raw.TsNs)+c.bootOffset).UTC()

	name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
	if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
		name = info.Name
	}

	process      := nullTermStr(raw.Comm[:])
	parentComm   := nullTermStr(raw.ParentComm[:])
	parentProcess := parentComm

	// Enrich with lineage if parent_comm is placeholder
	if c.lineage != nil && (parentComm == "" || parentComm == process) {
		if entry, ok := c.lineage.Lookup(raw.CgroupID, raw.PPID); ok {
			parentProcess = entry.Comm
		}
	}

	escType := escTypeNames[raw.EscType]
	if escType == "" {
		escType = fmt.Sprintf("unknown_%d", raw.EscType)
	}

	meta := map[string]any{
		"container":        name,
		"escalation_type":  escType,
	}

	switch raw.EscType {
	case escTypeSetUID:
		if raw.OldUID == 0xFFFFFFFF {
			meta["new_uid"] = raw.NewUID
		} else {
			meta["old_uid"] = raw.OldUID
			meta["new_uid"] = raw.NewUID
		}
	case escTypeSetGID:
		if raw.OldUID == 0xFFFFFFFF {
			meta["new_gid"] = raw.NewUID
		} else {
			meta["old_gid"] = raw.OldUID
			meta["new_gid"] = raw.NewUID
		}
	case escTypePtrace:
		meta["target_pid"] = raw.PtracePID
	case escTypeCap:
		capName := capNames[raw.Cap]
		if capName == "" {
			capName = fmt.Sprintf("CAP_%d", raw.Cap)
		}
		meta["capability"]     = capName
		meta["capability_num"] = raw.Cap
	}

	return event.EventEnvelope{
		Timestamp:     ts,
		CgroupID:      raw.CgroupID,
		ContainerName: name,
		PID:           raw.TGID,
		PPID:          raw.PPID,
		Process:       process,
		ParentProcess: parentProcess,
		EventType:     event.EventTypePrivEsc,
		Metadata:      meta,
	}
}

func parsePrivEscEvent(data []byte) privescEventRaw {
	var r privescEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.TsNs     = binary.LittleEndian.Uint64(data[8:16])
	r.TGID     = binary.LittleEndian.Uint32(data[16:20])
	r.PPID     = binary.LittleEndian.Uint32(data[20:24])
	copy(r.Comm[:], data[24:40])
	copy(r.ParentComm[:], data[40:56])
	r.OldUID    = binary.LittleEndian.Uint32(data[56:60])
	r.NewUID    = binary.LittleEndian.Uint32(data[60:64])
	r.EscType   = binary.LittleEndian.Uint32(data[64:68])
	r.Cap       = binary.LittleEndian.Uint32(data[68:72])
	r.PtracePID = binary.LittleEndian.Uint32(data[72:76])
	r.Pad       = binary.LittleEndian.Uint32(data[76:80])
	return r
}
