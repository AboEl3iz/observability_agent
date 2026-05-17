// Package msg defines all tea.Msg types exchanged within the TUI.
// Keeping messages in one place prevents import cycles and makes
// the event flow easy to trace.
package msg

import (
	"time"

	"ebpf/pkg/collector"
	"ebpf/pkg/event"
	"ebpf/pkg/graph"
	"ebpf/pkg/percentile"
)

// ─── Tick messages ────────────────────────────────────────────────────────────

// RenderTickMsg fires at the UI render rate (default 100 ms / ~10 FPS).
// It does NOT trigger a collection; it simply redraws from cached state.
type RenderTickMsg time.Time

// DataTickMsg is sent by the collector goroutine after each poll cycle
// completes.  It carries the full snapshot so the UI never reads from
// collector maps on the render goroutine.
type DataTickMsg time.Time

// ─── Data snapshot ────────────────────────────────────────────────────────────

// DataBatch is the immutable snapshot produced by one collector poll cycle.
// Views store their own copy and mark dirty=true when it changes.
type DataBatch struct {
	Timestamp time.Time
	CPU       []collector.CpuSample
	Mem       []collector.MemSample
	IO        []collector.IoSample
	Net       []collector.NetSummary
	Sys       []collector.SyscallSummary
	Events    []Event

	// Graph is a lock-free snapshot of the process graph, populated every
	// collect cycle.  Nil in demo mode unless a demo graph is generated.
	Graph *graph.Snapshot

	// Percentiles holds the precalculated HDR histogram snapshots for all latency metrics.
	// Keyed by metric key (e.g. "container_name:syscall_id").
	Percentiles map[string]percentile.WindowSnapshots
}

// DataMsg wraps a DataBatch for delivery via the BubbleTea message bus.
type DataMsg struct{ Batch DataBatch }

// ─── Event types ──────────────────────────────────────────────────────────────

// EventKind categorises a real-time event for colour-coding.
type EventKind int

const (
	EventKindInfo EventKind = iota
	EventKindTCP
	EventKindError
	EventKindOOM
	EventKindSlowSys
	EventKindSecurity
)

// Event is a single timestamped observability event emitted by a collector.
type Event struct {
	At        time.Time
	Kind      EventKind
	Container string
	Message   string
	Envelope  *event.EventEnvelope
	Count     int // number of merged/throttled occurrences
}

// ─── Navigation messages ──────────────────────────────────────────────────────

// NavTabMsg switches to the tab at Index.
type NavTabMsg struct{ Index int }

// NavDetailMsg opens the detail page for Container.
type NavDetailMsg struct{ Container string }

// NavBackMsg navigates back (detail → dashboard, search → dashboard, etc.).
type NavBackMsg struct{}

// ─── Search / filter ──────────────────────────────────────────────────────────

// SearchQueryMsg propagates the current filter string to the active view.
type SearchQueryMsg struct{ Query string }

// SearchClearMsg resets the active view's filter.
type SearchClearMsg struct{}

// ─── Sort ────────────────────────────────────────────────────────────────────

// SortColumnMsg asks the active table to sort by ColIndex (toggles asc/desc).
type SortColumnMsg struct{ ColIndex int }

// ─── Theme ───────────────────────────────────────────────────────────────────

// ThemeChangedMsg is published when the user changes the theme via the
// command palette.  The App propagates it to all child models.
type ThemeChangedMsg struct{ Name string }

// ─── Error ───────────────────────────────────────────────────────────────────

// ErrMsg wraps a non-fatal error to be shown in the status bar.
type ErrMsg struct{ Err error }
