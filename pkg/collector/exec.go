// Package collector — Phase 2: Full Execve Argument Capture
//
// ExecCollector reads the exec_events ring buffer and emits enriched
// EventEnvelope events with executable path, bounded argv, and process ancestry.
//
// Phase 1 integration: parent process name is looked up via LineageLookup.
// The BPF program (exec.c) already updates process_tree_map with comm_final=true
// on execve; this collector reads the resulting enriched event.
package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf/pkg/cgroup"
	"ebpf/pkg/event"
	"ebpf/pkg/lineage"
)

// exec event sizes — must match #defines in exec.c
const (
	execMaxArgs      = 20
	execMaxArgLen    = 128
	execMaxTotalLen  = 2048
	execPathLen      = 256
)

// execEventRaw mirrors struct exec_event from exec.c.
// Total size: 8+8+4+4+256+2048+4+4+1+1+6 = 2344 bytes.
type execEventRaw struct {
	CgroupID      uint64
	TsNs          uint64
	TGID          uint32
	PPID          uint32
	Path          [execPathLen]byte
	Argv          [execMaxTotalLen]byte
	ArgvCount     uint32
	ArgvTotalLen  uint32
	ArgvTruncated uint8
	PathTruncated uint8
	Pad           [6]byte
}

// ExecCollector reads execve events from exec_events ring buffer.
type ExecCollector struct {
	execRB     *ringbuf.Reader
	lineage    lineage.LineageLookup
	resolver   *cgroup.Resolver
	writer     event.SecurityEventWriter
	bootOffset int64
	log        *slog.Logger
}

// NewExecCollector creates an ExecCollector.
//   - execRBMap: BPF map "exec_events" (ring buffer)
//   - lookup:    LineageLookup for parent process ancestry
//   - writer:    security event output (nil = suppress)
func NewExecCollector(
	execRBMap *ebpf.Map,
	lookup lineage.LineageLookup,
	resolver *cgroup.Resolver,
	writer event.SecurityEventWriter,
	bootOffset int64,
	log *slog.Logger,
) (*ExecCollector, error) {
	rd, err := ringbuf.NewReader(execRBMap)
	if err != nil {
		return nil, fmt.Errorf("opening exec_events ring buffer: %w", err)
	}
	return &ExecCollector{
		execRB:     rd,
		lineage:    lookup,
		resolver:   resolver,
		writer:     writer,
		bootOffset: bootOffset,
		log:        log,
	}, nil
}

// Close releases resources.
func (c *ExecCollector) Close() {
	if c.execRB != nil {
		c.execRB.Close()
	}
}

// ReadExecEvents drains all pending execve events from the ring buffer.
func (c *ExecCollector) ReadExecEvents() ([]event.EventEnvelope, error) {
	var events []event.EventEnvelope
	rawSize := int(unsafe.Sizeof(execEventRaw{}))

	for {
		c.execRB.SetDeadline(time.Now().Add(1 * time.Millisecond))
		rec, err := c.execRB.Read()
		if err != nil {
			break
		}
		if len(rec.RawSample) < rawSize {
			c.log.Warn("short exec_events record", "len", len(rec.RawSample))
			continue
		}

		raw := parseExecEvent(rec.RawSample)
		env := c.execEventToEnvelope(&raw)
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

func (c *ExecCollector) execEventToEnvelope(raw *execEventRaw) event.EventEnvelope {
	ts := time.Unix(0, int64(raw.TsNs)+c.bootOffset).UTC()

	name := fmt.Sprintf("cgroup:%d", raw.CgroupID)
	if info, ok := c.resolver.Lookup(raw.CgroupID); ok {
		name = info.Name
	}

	process := nullTermStr(raw.Path[:])
	// Use basename for Process field (last component of path)
	if idx := strings.LastIndexByte(process, '/'); idx >= 0 {
		process = process[idx+1:]
	}

	parentProcess := ""
	if c.lineage != nil {
		if entry, ok := c.lineage.Lookup(raw.CgroupID, raw.PPID); ok {
			parentProcess = entry.Comm
		}
	}

	// Decode packed argv: null-separated strings
	argv := decodeArgv(raw.Argv[:], raw.ArgvTotalLen)

	return event.EventEnvelope{
		Timestamp:     ts,
		CgroupID:      raw.CgroupID,
		ContainerName: name,
		PID:           raw.TGID,
		PPID:          raw.PPID,
		Process:       process,
		ParentProcess: parentProcess,
		EventType:     event.EventTypeExec,
		Metadata: map[string]any{
			"container":      name,
			"full_path":      nullTermStr(raw.Path[:]),
			"argv":           argv,
			"argv_truncated": raw.ArgvTruncated == 1,
			"path_truncated": raw.PathTruncated == 1,
			"arg_count":      raw.ArgvCount,
		},
	}
}

// decodeArgv splits a null-separated byte slice into a string slice.
// Each argument in the BPF buffer is a null-terminated string.
func decodeArgv(buf []byte, totalLen uint32) []string {
	if totalLen == 0 || int(totalLen) > len(buf) {
		return nil
	}
	data := buf[:totalLen]
	var args []string
	for {
		idx := 0
		for idx < len(data) && data[idx] != 0 {
			idx++
		}
		if idx > 0 {
			args = append(args, string(data[:idx]))
		}
		if idx >= len(data) {
			break
		}
		data = data[idx+1:] // skip null terminator
	}
	return args
}

func parseExecEvent(data []byte) execEventRaw {
	var r execEventRaw
	r.CgroupID = binary.LittleEndian.Uint64(data[0:8])
	r.TsNs     = binary.LittleEndian.Uint64(data[8:16])
	r.TGID     = binary.LittleEndian.Uint32(data[16:20])
	r.PPID     = binary.LittleEndian.Uint32(data[20:24])
	copy(r.Path[:], data[24:24+execPathLen])
	argvStart := 24 + execPathLen
	copy(r.Argv[:], data[argvStart:argvStart+execMaxTotalLen])
	end := argvStart + execMaxTotalLen
	r.ArgvCount    = binary.LittleEndian.Uint32(data[end:end+4])
	r.ArgvTotalLen = binary.LittleEndian.Uint32(data[end+4:end+8])
	r.ArgvTruncated = data[end+8]
	r.PathTruncated = data[end+9]
	return r
}
