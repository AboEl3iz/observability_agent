<div align="center">

# eBPF Container Observability Agent

**Deep kernel-level visibility into every container — zero instrumentation, near-zero overhead.**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-Powered-FF6B35?style=for-the-badge&logo=linux&logoColor=white)](https://ebpf.io)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%205.10%2B-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org)
[![Kernel: cgroup v2](https://img.shields.io/badge/cgroup-v2-9B59B6?style=for-the-badge&logo=linux&logoColor=white)](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](docker-compose.yml)
[![Build](https://img.shields.io/badge/Build-make%20build-4CAF50?style=for-the-badge&logo=gnu-make&logoColor=white)](#building)

</div>

---

## What is this?

A production-grade eBPF observability agent written in Go and C that hooks directly into the Linux kernel to provide **deep, real-time insights** into container behaviour — without any instrumentation, sidecars, or application changes.

It resolves kernel-level PIDs and cgroup IDs to human-readable container names (Docker, containerd/k8s) and surfaces the data through a rich interactive TUI with 8 specialised tabs.

---

## Feature Matrix

### 📊 Performance Telemetry (M1–M4, M6)

| Module | BPF Program | Hook Points | What it tracks |
|--------|-------------|-------------|----------------|
| **M1 CPU** | `cpu.c` | `sched_switch`, `sched_process_wait` | CPU time (s/Δt), runqueue latency, context switches/s, live thread count |
| **M2 Memory** | `memory.c` | `mm_page_fault_user`, `oom_kill_victim` | RSS (MB), memory limit, page faults/s, real-time OOM-kill events |
| **M3 Disk I/O** | `io.c` | `block_rq_insert`, `block_rq_complete`, `sys_enter_openat` | Read/Write KB/s, R/W latency (ms), real-time file-open stream |
| **M4 Network** | `network.c` | `inet_sock_set_state`, `tcp_retransmit_skb`, `tcp_sendmsg` | Active flows, ESTABLISHED/TIME_WAIT/CLOSE_WAIT, retransmits, real-time TCP transitions |
| **M6 Syscall** | `syscall.c` | `raw_syscalls:sys_enter/exit` | Top 5 syscalls per container, failure counts, avg latency, slow syscall alerts (>50 ms) |

### 🔒 Security Telemetry — Phase 1–5

| Phase | BPF Program | Kernel Hook | What it detects |
|-------|-------------|-------------|-----------------|
| **Ph1 Lineage** | `lineage.c` | `sched_process_fork` | Full process ancestry tree (up to depth 8) for event enrichment |
| **Ph2 Exec** | `exec.c` | `sys_enter_execve` | Every `execve()` inside a container: full argv, parent chain, PID |
| **Ph3 DNS** | `dns.c` | `sys_enter_sendmsg`, `sys_enter_sendmmsg` | DNS query interception (UDP/53) with query name and record type |
| **Ph4 PrivEsc** | `privesc.c` | `sys_enter_setuid/setgid`, `sys_enter_ptrace`, `kprobe:cap_capable` | `setuid`, `setgid`, `ptrace`, capability checks (with full `CAP_*` name decoding) |
| **Ph5 Escape** | `escape.c` | `sys_enter_mount`, `sys_enter_unshare`, `sys_enter_pivot_root` | Container escape indicators: mount, namespace unshare, pivot_root — with MS_*/CLONE_* flag decoding and runtime-initiated tagging |

---

## TUI — 8 Specialised Tabs

```
╭─ Overview ─ CPU ─ Memory ─ I/O ─ Network ─ Syscall ─ Events ─ Graphs ─╮
│  1          2     3        4      5          6         7        8       │
```

| Key | Tab | Contents |
|-----|-----|----------|
| `1` | **Overview** | Container summary table — all metrics in one glance |
| `2` | **CPU** | Per-container CPU seconds, runqueue latency, context switches, threads |
| `3` | **Memory** | RSS, limit, page faults/s, OOM kill events |
| `4` | **I/O** | Block read/write KB/s, latency, file-open event stream |
| `5` | **Network** | TCP flows, connection state distribution, retransmit heatmap |
| `6` | **Syscall** | Top-5 syscalls ranked by frequency with failure rates and latency |
| `7` | **Events** | Live, colour-coded security event stream with `[DNS]` `[EXEC]` `[PRIV]` `[ESCP]` badges |
| `8` | **Graphs** | System-wide sparkline graphs per container (CPU, Mem, I/O R/W, Net flows) |

### Container Detail Cockpit (`Enter` from any table row)

Pressing `Enter` on any container opens a full-screen cockpit:

- **Header** — container name, runtime, state  
- **Resources** — live CPU / Mem / I/O numbers  
- **Live Graphs** — 5 sparklines (CPU, Mem, I/O Read, I/O Write, Syscall latency)  
- **Network** — TCP flows, retransmits  
- **Top Syscalls** — ranked table with failure rates  
- **Event Timeline** — filterable chronological stream with full `[DNS]` `[EXEC]` `[PRIV]` `[ESCP]` badge rendering  

---

## Architecture

```
┌─────────────────── Linux Kernel ────────────────────────────────────────┐
│                                                                          │
│  tracepoints / kprobes                                                   │
│  sched · block · sock · tcp · raw_syscalls · oom                        │
│  fork · execve · sendmsg · setuid · setgid · mount · unshare           │
│                                                                          │
│  eBPF Programs (C)                                                       │
│  cpu.c  memory.c  io.c  network.c  syscall.c                            │
│  lineage.c  exec.c  dns.c  privesc.c  escape.c                          │
│                                                                          │
│  BPF Hash Maps / Ring Buffers ←── pinned at /sys/fs/bpf/ebpf-agent     │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ cilium/ebpf
┌─────────────────── Go Agent ─────▼──────────────────────────────────────┐
│                                                                          │
│  pkg/collector/          pkg/cgroup/          pkg/lineage/              │
│  CpuCollector            Resolver             LineageLookup             │
│  MemCollector            Docker name lookup   Process ancestry tree     │
│  IoCollector             cri-containerd       max depth = 8             │
│  NetworkCollector        /proc + /sys walk                               │
│  SyscallCollector                                                        │
│  DnsCollector            pkg/event/                                     │
│  ExecCollector           EventEnvelope        SecurityEventWriter       │
│  PrivEscCollector        EventType            (TUI / stderr / file)     │
│  EscapeCollector                                                         │
│                                                                          │
│  internal/tui/app/       internal/tui/views/                            │
│  Root BubbleTea model    Overview · CPU · Memory · IO                   │
│  Dual-tick engine        Network · Syscall · Events · Graphs             │
│  Theme engine (6 themes) Detail cockpit (sparklines + event timeline)   │
│  Command palette         Searchbar · Modal · Tabbar · Statusbar          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Building

### Prerequisites

| Tool | Purpose |
|------|---------|
| Linux kernel **≥ 5.10** with `CONFIG_BPF=y` | eBPF runtime |
| `clang` + `llvm` | Compile BPF C programs |
| Go **1.21+** | Build the Go agent |
| `cgroup v2` mounted | Container cgroup resolution |

```bash
# Full build — compile all 10 BPF objects + Go binaries
make build

# BPF objects only
make bpf

# Go binaries only (BPF objects must already exist)
make go-build

# Run tests (no root, no BPF required)
make test

# Clean everything (BPF objects, binaries, pinned maps)
make clean
```

---

## Usage

### TUI (Recommended)

```bash
# Full TUI with all collectors + security telemetry
make run-tui

# Demo mode — no root, no BPF, generates realistic synthetic data
make run-tui-demo

# Or run the binary directly
sudo ./tui [flags]
```

#### TUI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--containers-only` | `false` | Hide host cgroups, show only Docker/containerd containers |
| `--interval <dur>` | `2s` | Metrics polling interval |
| `--show-files` | `false` | Stream real-time file open events (M3) |
| `--show-tcp` | `false` | Stream real-time TCP state transitions (M4) |
| `--show-slow-sys` | `false` | Alert on syscalls blocking > 50 ms (M6) |
| `--top <N>` | `0` | Limit tables to top N rows (0 = unlimited) |
| `--theme <name>` | `github-dark` | UI theme |
| `--demo` | `false` | Synthetic data mode — no root required |

#### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1`–`8` | Jump to tab |
| `Tab` / `]` | Next tab |
| `Shift+Tab` / `[` | Previous tab |
| `Enter` | Open container cockpit |
| `Esc` | Back to dashboard |
| `↑` / `k`, `↓` / `j` | Scroll |
| `g` / `G` | Top / bottom (live-follow) |
| `PgUp` / `PgDn` | Half-page scroll |
| `/` | Filter mode |
| `p` | Pause data (inside cockpit) |
| `T` | Cycle through 6 themes |
| `:` | Command palette |
| `?` | Help overlay |
| `q` / `Ctrl+C` | Quit |

### Observer CLI

```bash
# Containers only (M1–M4, M6)
make run

# All cgroups including host
make run-all

# Full security telemetry (all 10 BPF programs)
make run-security

# File + TCP + slow-syscall event stream
make run-files
```

---

## Docker / Production Deployment

```bash
# Build image and start in background
make docker-run
# or
docker-compose up -d
```

The container:

- Runs in the **host PID namespace** for cgroup resolution
- Uses **capability-scoped** permissions (no `--privileged`):  
  `BPF` · `PERFMON` · `SYS_ADMIN` · `SYS_RESOURCE` · `DAC_READ_SEARCH` · `NET_ADMIN`
- Exposes `HTTP :8080` for health checks — `GET /healthz`
- Mounts `/sys/fs/cgroup`, `/proc`, `/sys/fs/bpf` from the host

---

## Security Event Reference

### `[EXEC]` — Process Execution
Emitted on every `execve()` inside a container. Fields: `argv`, parent chain.

### `[DNS ]` — DNS Query
Intercepted at `sendmsg`/`sendmmsg` before the packet hits the wire. Fields: `query` (domain name), `query_type` (A, AAAA, etc.).

### `[PRIV]` — Privilege Escalation
Detected operations:

| op | Trigger | Key metadata |
|----|---------|--------------|
| `setuid` | `sys_enter_setuid` | `old_uid`, `new_uid` |
| `setgid` | `sys_enter_setgid` | `old_gid`, `new_gid` |
| `ptrace` | `sys_enter_ptrace` | `target_pid` |
| `cap_capable` | `kprobe:cap_capable` | `capability` (e.g. `CAP_SYS_ADMIN`) |

### `[ESCP]` — Container Escape Indicator
Suspicious namespace/mount operations:

| indicator | Trigger | Key metadata |
|-----------|---------|--------------|
| `mount` | `sys_enter_mount` | `namespace_flags` (e.g. `MS_BIND\|MS_REC`) |
| `unshare` | `sys_enter_unshare` | `namespace_flags` (e.g. `CLONE_NEWNS\|CLONE_NEWUSER`) |
| `pivot_root` | `sys_enter_pivot_root` | `runtime_initiated: true/false` |

> **Note:** `runtime_initiated: true` means the syscall originated from a known container runtime (`runc`, `containerd-shim`, `dockerd`, `crun`, `podman`). These are not suppressed — they are tagged so downstream consumers can filter if desired.

---

## Themes

Press `T` to cycle through 6 built-in themes:

`github-dark` · `nord` · `gruvbox` · `tokyo-night` · `catppuccin` · `solarized`

---

## License

eBPF C programs are licensed under **GPL-2.0** (required for kernel access).  
Go agent code is available under the same license.
