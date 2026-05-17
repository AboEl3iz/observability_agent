package exporter

import (
	"ebpf/pkg/collector"
	"ebpf/pkg/event"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusExporter holds all the Prometheus metrics.
type PrometheusExporter struct {
	// M1 CPU
	CpuSeconds        *prometheus.GaugeVec
	RunqLatency       *prometheus.GaugeVec
	CtxSwitchesPerSec *prometheus.GaugeVec
	Threads           *prometheus.GaugeVec

	// M2 Memory
	MemoryRSS        *prometheus.GaugeVec
	MemoryLimit      *prometheus.GaugeVec
	PageFaultsPerSec *prometheus.GaugeVec

	// M3 I/O
	DiskReadBytesPerSec  *prometheus.GaugeVec
	DiskWriteBytesPerSec *prometheus.GaugeVec
	DiskReadLatencyMs    *prometheus.GaugeVec
	DiskWriteLatencyMs   *prometheus.GaugeVec

	// M4 Network
	NetActiveFlows *prometheus.GaugeVec
	NetEstablished *prometheus.GaugeVec
	NetTimeWait    *prometheus.GaugeVec
	NetCloseWait   *prometheus.GaugeVec
	NetRetransmits *prometheus.GaugeVec

	// M6 Syscall
	SyscallCount    *prometheus.GaugeVec
	SyscallFailures *prometheus.GaugeVec
	SyscallLatency  *prometheus.GaugeVec

	// Security Events
	SecurityEvents *prometheus.CounterVec

	// Individual Detailed Security/OOM Metrics
	OomKills         *prometheus.CounterVec
	DnsQueries       *prometheus.CounterVec
	LineageForks     *prometheus.CounterVec
	ExecEvents       *prometheus.CounterVec
	PrivEscalations  *prometheus.CounterVec
	EscapeIndicators *prometheus.CounterVec
}

// NewPrometheusExporter creates and registers all metrics with separate Kubernetes labels.
func NewPrometheusExporter(reg prometheus.Registerer) *PrometheusExporter {
	factory := promauto.With(reg)
	labels := []string{"namespace", "pod", "container"}

	return &PrometheusExporter{
		CpuSeconds: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_cpu_seconds",
			Help: "CPU seconds consumed by container",
		}, labels),
		RunqLatency: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_runq_latency_seconds",
			Help: "Run queue latency in seconds",
		}, labels),
		CtxSwitchesPerSec: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_ctx_switches_per_sec",
			Help: "Context switches per second",
		}, labels),
		Threads: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_threads",
			Help: "Number of threads",
		}, labels),

		MemoryRSS: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_memory_rss_bytes",
			Help: "Memory RSS in bytes",
		}, labels),
		MemoryLimit: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_memory_limit_bytes",
			Help: "Memory limit in bytes",
		}, labels),
		PageFaultsPerSec: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_page_faults_per_sec",
			Help: "Page faults per second",
		}, labels),

		DiskReadBytesPerSec: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_disk_read_bytes_per_sec",
			Help: "Disk read bytes per second",
		}, labels),
		DiskWriteBytesPerSec: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_disk_write_bytes_per_sec",
			Help: "Disk write bytes per second",
		}, labels),
		DiskReadLatencyMs: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_disk_read_latency_ms",
			Help: "Disk average read latency in ms",
		}, labels),
		DiskWriteLatencyMs: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_disk_write_latency_ms",
			Help: "Disk average write latency in ms",
		}, labels),

		NetActiveFlows: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_net_active_flows",
			Help: "Number of active network flows",
		}, labels),
		NetEstablished: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_net_established",
			Help: "Number of established connections",
		}, labels),
		NetTimeWait: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_net_time_wait",
			Help: "Number of connections in TIME_WAIT",
		}, labels),
		NetCloseWait: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_net_close_wait",
			Help: "Number of connections in CLOSE_WAIT",
		}, labels),
		NetRetransmits: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_net_retransmits_total",
			Help: "Total TCP retransmits",
		}, labels),

		SyscallCount: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_syscall_count",
			Help: "Number of syscalls per tick",
		}, append(labels, "syscall")),
		SyscallFailures: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_syscall_failures",
			Help: "Number of syscall failures per tick",
		}, append(labels, "syscall")),
		SyscallLatency: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_syscall_latency_ms",
			Help: "Average syscall latency in ms",
		}, append(labels, "syscall")),

		SecurityEvents: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_security_events_total",
			Help: "Total security events detected",
		}, append(labels, "type")),

		OomKills: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_oom_kills_total",
			Help: "Total OOM kills detected per container",
		}, labels),
		DnsQueries: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_dns_queries_total",
			Help: "Total DNS queries intercepted",
		}, append(labels, "query_type")),
		LineageForks: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_lineage_forks_total",
			Help: "Total lineage process forks observed",
		}, labels),
		ExecEvents: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_exec_events_total",
			Help: "Total process executions observed",
		}, labels),
		PrivEscalations: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_privilege_escalations_total",
			Help: "Total privilege escalation indicators observed",
		}, labels),
		EscapeIndicators: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_escape_indicators_total",
			Help: "Total container escape indicators observed",
		}, labels),
	}
}

// splitK8sLabels extracts Kubernetes namespace, pod name, and container name.
// When containerName is formatted as "namespace/pod/container", it splits the values.
// In non-Kubernetes modes (e.g. Host/Docker), it populates namespace="" and pod="",
// mapping the direct name into the container label for backwards compatibility.
func splitK8sLabels(containerName string) (string, string, string) {
	parts := strings.Split(containerName, "/")
	if len(parts) == 3 {
		return parts[0], parts[1], parts[2]
	}
	return "", "", containerName
}

// UpdateCPU updates CPU metrics.
func (e *PrometheusExporter) UpdateCPU(samples []collector.CpuSample) {
	for _, s := range samples {
		ns, pod, container := splitK8sLabels(s.ContainerName)
		e.CpuSeconds.WithLabelValues(ns, pod, container).Set(s.CPUSeconds)
		e.RunqLatency.WithLabelValues(ns, pod, container).Set(s.RunqLatencySeconds)
		e.CtxSwitchesPerSec.WithLabelValues(ns, pod, container).Set(s.CtxSwitchesPerSec)
		e.Threads.WithLabelValues(ns, pod, container).Set(float64(s.ThreadCount))
	}
}

// UpdateMemory updates Memory metrics.
func (e *PrometheusExporter) UpdateMemory(samples []collector.MemSample) {
	for _, s := range samples {
		ns, pod, container := splitK8sLabels(s.ContainerName)
		e.MemoryRSS.WithLabelValues(ns, pod, container).Set(float64(s.MemoryBytes))
		e.MemoryLimit.WithLabelValues(ns, pod, container).Set(float64(s.MemoryLimitBytes))
		e.PageFaultsPerSec.WithLabelValues(ns, pod, container).Set(s.FaultsPerSec)
	}
}

// UpdateIO updates I/O metrics.
func (e *PrometheusExporter) UpdateIO(samples []collector.IoSample) {
	for _, s := range samples {
		ns, pod, container := splitK8sLabels(s.ContainerName)
		e.DiskReadBytesPerSec.WithLabelValues(ns, pod, container).Set(s.ReadBytesPerSec)
		e.DiskWriteBytesPerSec.WithLabelValues(ns, pod, container).Set(s.WriteBytesPerSec)
		e.DiskReadLatencyMs.WithLabelValues(ns, pod, container).Set(s.AvgReadLatencyMs)
		e.DiskWriteLatencyMs.WithLabelValues(ns, pod, container).Set(s.AvgWriteLatencyMs)
	}
}

// UpdateNetwork updates Network metrics.
func (e *PrometheusExporter) UpdateNetwork(samples []collector.NetSummary) {
	for _, s := range samples {
		ns, pod, container := splitK8sLabels(s.ContainerName)
		e.NetActiveFlows.WithLabelValues(ns, pod, container).Set(float64(s.ActiveFlows))
		e.NetEstablished.WithLabelValues(ns, pod, container).Set(float64(s.Established))
		e.NetTimeWait.WithLabelValues(ns, pod, container).Set(float64(s.TimeWait))
		e.NetCloseWait.WithLabelValues(ns, pod, container).Set(float64(s.CloseWait))
		e.NetRetransmits.WithLabelValues(ns, pod, container).Set(float64(s.TotalRetransmits))
	}
}

// UpdateSyscalls updates Syscall metrics.
func (e *PrometheusExporter) UpdateSyscalls(samples []collector.SyscallSummary) {
	for _, s := range samples {
		ns, pod, container := splitK8sLabels(s.ContainerName)
		e.SyscallCount.WithLabelValues(ns, pod, container, s.SyscallName).Set(float64(s.Count))
		e.SyscallFailures.WithLabelValues(ns, pod, container, s.SyscallName).Set(float64(s.Failures))
		e.SyscallLatency.WithLabelValues(ns, pod, container, s.SyscallName).Set(s.AvgLatencyMs)
	}
}

// UpdateOOM increments OOM kill metrics.
func (e *PrometheusExporter) UpdateOOM(containerName string) {
	ns, pod, container := splitK8sLabels(containerName)
	e.OomKills.WithLabelValues(ns, pod, container).Inc()
}

// PrometheusSecurityEventWriter wraps an existing writer and also updates metrics.
type PrometheusSecurityEventWriter struct {
	Inner    event.SecurityEventWriter
	Exporter *PrometheusExporter
}

func (w *PrometheusSecurityEventWriter) Write(ev event.EventEnvelope) {
	ns, pod, container := splitK8sLabels(ev.ContainerName)
	w.Exporter.SecurityEvents.WithLabelValues(ns, pod, container, string(ev.EventType)).Inc()

	// Update specific security event counters
	switch ev.EventType {
	case event.EventTypeFork:
		w.Exporter.LineageForks.WithLabelValues(ns, pod, container).Inc()
	case event.EventTypeExec:
		w.Exporter.ExecEvents.WithLabelValues(ns, pod, container).Inc()
	case event.EventTypeDNSQuery:
		qtype := ""
		if ev.Metadata != nil {
			if qt, ok := ev.Metadata["query_type"].(string); ok {
				qtype = qt
			}
		}
		w.Exporter.DnsQueries.WithLabelValues(ns, pod, container, qtype).Inc()
	case event.EventTypePrivEsc:
		w.Exporter.PrivEscalations.WithLabelValues(ns, pod, container).Inc()
	case event.EventTypeEscapeIndicator:
		w.Exporter.EscapeIndicators.WithLabelValues(ns, pod, container).Inc()
	}

	if w.Inner != nil {
		w.Inner.Write(ev)
	}
}
