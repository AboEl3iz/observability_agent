# eBPF Container Observability Agent

A high-performance, low-overhead container observability tool built with eBPF and Go. It tracks critical system metrics and events at the kernel level and maps them to human-readable container names.

## Features

This project uses custom eBPF programs to monitor five key areas of system activity, resolving kernel-level PIDs and cgroups to container identities (Docker/containerd):

* **M1: CPU & Thread Observability** (`cpu.c`)
  * CPU time consumption (on-CPU scheduling)
  * Runqueue wait latency
  * Context switches per second
  * Live thread counts
* **M2: Memory & OOM Kill** (`memory.c`)
  * RSS usage proxy (via page faults)
  * OOM (Out Of Memory) kill victim tracking
* **M3: Disk I/O & Filesystem** (`io.c`)
  * Block device read/write throughput (KB/s)
  * Disk I/O latency
  * Real-time file open events (`sys_enter_openat`)
* **M4: Network Connection Tracking** (`network.c`)
  * Active TCP flow tracking
  * State distribution (ESTABLISHED, TIME_WAIT, CLOSE_WAIT)
  * TCP retransmit tracking
  * Real-time TCP state transition events
* **M6: Syscall Observability** (`syscall.c`)
  * Top 5 most frequent syscalls per container
  * Syscall failure counts
  * Average syscall latency
  * Real-time slow syscall detection (> 50ms)

## Interfaces

The project provides two distinct user interfaces:

1. **TUI (`cmd/tui`)**: A rich, interactive terminal UI built with `bubbletea` and `lipgloss`. Features live-updating metric cards and a real-time event stream.
2. **Observer (`cmd/observer`)**: A standard CLI that prints updating ASCII tables and logs events to standard error.

## Building

**Prerequisites:**
* Linux kernel with eBPF support
* `clang` and `llvm` for compiling BPF C code
* Go 1.21+

To build both the eBPF objects and the Go binaries:

```bash
# Compile eBPF C code and build Go binaries
make build

# To compile only the eBPF code
make bpf

# To compile only the Go code (requires pre-built BPF objects)
make go-build
```

## Usage

Both the `tui` and `observer` binaries support a similar set of flags.

### TUI

```bash
sudo ./tui [flags]
```

**Flags:**
* `--interval 2s`: Metrics polling interval
* `--containers-only`: Hide host processes, show only Docker/cri containers
* `--show-files`: Stream real-time file open events (M3)
* `--show-tcp`: Stream real-time TCP state transitions (M4)
* `--show-slow-sys`: Stream slow syscall warnings (M6)
* `--top N`: Limit tables to the top N rows (0 = show all)
* `--demo`: Run in simulation mode (no root/BPF required, generates fake data)

**TUI Controls:**
* `Tab`: Switch focus between Metrics (top) and Events (bottom) panes
* `Up/Down` or `k/j`: Scroll the focused pane
* `g` / `G`: Scroll to top / follow live (auto-scroll)
* `q` or `Ctrl+C`: Quit

### Observer

```bash
sudo ./observer [flags]
```

Accepts the same flags as the TUI (except `--demo`). Outputs self-refreshing ASCII tables directly to the terminal.

## Architecture

* **eBPF C Code** (`ebpf/*.c`): Attaches to kernel tracepoints (`sched`, `block`, `sock`, `tcp`, `raw_syscalls`, `oom`). Uses BPF Hash maps for state tracking and Ringbuffers for streaming discrete events (like OOM kills or file opens).
* **Go Collectors** (`pkg/collector/`): Read from the BPF maps, process raw data, and calculate delta metrics (like per-second rates).
* **Cgroup Resolver** (`pkg/cgroup/`): Maps kernel cgroup IDs to human-readable container names by reading `/proc` and `/sys/fs/cgroup`.

## License

eBPF programs are licensed under GPL-2.0.
