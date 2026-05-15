// Package event defines the shared event envelope used by all security
// telemetry modules (Phase 1–5).
//
// All timestamps are wall-clock UTC (RFC3339Nano), converted from
// bpf_ktime_get_ns() using the boot-time offset computed at agent startup.
// Raw ktime values are NEVER exposed in emitted events.
package event

import "time"

// EventType identifies the source module of a security event.
type EventType string

const (
	EventTypeFork              EventType = "process_fork"
	EventTypeExec              EventType = "exec"
	EventTypeDNSQuery          EventType = "dns_query"
	EventTypePrivEsc           EventType = "privilege_escalation"
	EventTypeEscapeIndicator   EventType = "escape_indicator"
)

// EventEnvelope is the normalized event structure emitted by all security
// telemetry collectors. It is designed to be serializable to JSON and
// extensible via the Metadata map without breaking existing consumers.
//
// Design contract:
//   - Timestamp is always wall-clock UTC, never raw ktime.
//   - ParentProcess is populated by LineageLookup enrichment in Go.
//   - AncestryTruncated is true when the ancestry chain was cut at maxDepth=8.
//   - Metadata holds module-specific fields (argv, dns query, escalation type, etc.)
type EventEnvelope struct {
	// Common fields — present in every event
	Timestamp         time.Time         `json:"timestamp"`
	CgroupID          uint64            `json:"cgroup_id"`
	ContainerName     string            `json:"container,omitempty"` // empty = non-container process
	PID               uint32            `json:"pid"`
	PPID              uint32            `json:"ppid"`
	Process           string            `json:"process"`
	ParentProcess     string            `json:"parent_process,omitempty"`
	EventType         EventType         `json:"event_type"`
	AncestryTruncated bool              `json:"ancestry_truncated,omitempty"`

	// Module-specific payload
	Metadata map[string]any `json:"metadata,omitempty"`
}

// SecurityEventWriter is the output interface for security events.
// Implementations may write to stderr, a TUI channel, or a JSON log file
// without requiring changes to the collectors.
//
// All Phase 1–5 collectors accept a SecurityEventWriter at construction time.
// The --show-security flag wires up a StderrWriter; future TUI / file writers
// can be added as non-breaking additions.
type SecurityEventWriter interface {
	Write(ev EventEnvelope)
}
