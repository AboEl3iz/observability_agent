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

[![Watch the Demo](https://github.com/AboEl3iz/observability_agent/raw/main/videos/output.gif)](https://github.com/AboEl3iz/observability_agent/blob/main/videos/video_demo.mp4)
---

## Feature Matrix

###  Performance Telemetry (M1–M4, M6)

| Module | BPF Program | Hook Points | What it tracks |
|--------|-------------|-------------|----------------|
| **M1 CPU** | `cpu.c` | `sched_switch`, `sched_process_wait` | CPU time (s/Δt), runqueue latency, context switches/s, live thread count, **NUMA balancing (local % vs remote %)** |
| **M2 Memory** | `memory.c` | `exceptions/page_fault_user`, `oom/mark_victim` | VIRT, RSS, PSS, Shared (MB), **Major/Minor page faults/s**, **PSI Pressure (some % \| full %)**, **TLB miss rate proxy**, real-time OOM-kill events |
| **M3 Disk I/O** | `io.c` | `block_rq_insert`, `block_rq_complete`, `sys_enter_openat` | Read/Write KB/s, R/W latency (ms), real-time file-open stream |
| **M4 Network** | `network.c` | `inet_sock_set_state`, `tcp_retransmit_skb`, `tcp_sendmsg` | Active flows, ESTABLISHED/TIME_WAIT/CLOSE_WAIT, retransmits, real-time TCP transitions |
| **M6 Syscall** | `syscall.c` | `raw_syscalls:sys_enter/exit` | Top 5 syscalls per container, failure counts, avg latency, slow syscall alerts (>50 ms) |


###  Security Telemetry — Phase 1–5

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
| `2` | **CPU** | CPU time, runqueue latency, context switches, thread count, **NUMA Balancing (local % / remote %)** |
| `3` | **Memory** | **VIRT, RSS, PSS, Shared (MB)**, **major/minor page faults/s**, **PSI Pressure**, **TLB Miss Rate**, OOM kill events |
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

## Docker / Containerized Production Deployment

```bash
# Build image and start in background
make docker-run
# or
docker-compose up -d
```

The container:
- Runs in the **host PID namespace** for cgroup resolution.
- Uses **capability-scoped** permissions (no `--privileged` required): `BPF` · `PERFMON` · `SYS_ADMIN` · `SYS_RESOURCE` · `DAC_READ_SEARCH` · `NET_ADMIN`.
- Exposes `HTTP :8080` for health checks — `GET /healthz` and Prometheus scraping — `GET /metrics`.
- Mounts `/sys/fs/cgroup`, `/proc`, `/sys/fs/bpf` from the host.

---

## Native Host Systemd Deployment (Recommended)

For VM-based production environments, running the agent as a native `systemd` service is recommended. It eliminates containerization overhead and capability mapping complexities.

We provide a systemd service unit with **production-grade sandboxing** (using `CapabilityBoundingSet` and `ProtectSystem=strict` to restrict the process's access).

### 1. Installation
Build BPF programs, compile the Go binary, install to path, and register the service:
```bash
sudo make install
```

This installs:
* Binary: `/usr/local/bin/ebpf-observer`
* eBPF Objects: `/usr/local/share/ebpf-observer/*.o`
* Systemd Service: `/etc/systemd/system/ebpf-observer.service`
* Config Options: `/etc/default/ebpf-observer`

### 2. Service Management
```bash
# Start the service
sudo systemctl start ebpf-observer

# View live service logs
make systemd-logs
# or: journalctl -u ebpf-observer -f

# Check service status
make systemd-status
# or: systemctl status ebpf-observer

# Stop the service
sudo systemctl stop ebpf-observer
```

### 3. Configuration
Options can be configured by editing `/etc/default/ebpf-observer`:
```bash
# Example /etc/default/ebpf-observer
EBPF_OBSERVER_OPTS="--containers-only --show-security --rich-mem"
```

### 4. Uninstallation
To completely stop, disable, and clean up the service:
```bash
sudo make uninstall
```

---

## Prometheus & Grafana Monitoring Stack

We provide a complete out-of-the-box monitoring stack containing the eBPF Observer agent, Prometheus, and Grafana.

### 1. Start the Local Compose Stack
```bash
# Build the agent and start all containers sharing the host network
make monitoring-up
```
Once started, the services are available at:
* **eBPF Observer metrics**: `http://localhost:8080/metrics`
* **Prometheus**: `http://localhost:9090` (configured to scrape eBPF Observer)
* **Grafana**: `http://localhost:3000` (default login: `admin` / `admin`)

### 2. Stop the Local Compose Stack
```bash
make monitoring-down
```

### 3. Grafana Dashboard
We include a python script (`monitoring/gen_dashboard.py`) to auto-generate a comprehensive 46-panel dashboard JSON located at `monitoring/grafana/provisioning/dashboards/ebpf_observer.json`.

The dashboard is auto-provisioned inside Grafana and split into:
* **Overview**: Container summary, CPU/Memory gauges, and OOM kills.
* **CPU**: CPU usage, runqueue latency, thread count, and NUMA balancing metrics.
* **Memory**: VIRT/RSS/PSS/Shared usage, split major/minor page faults, PSI pressure, and TLB miss rate.
* **Disk I/O**: Block read/write rates and file open requests.
* **Network**: Active TCP flows and state distribution.
* **Syscalls**: Top system calls and slow syscall rates.
* **Security Events**: Exec count, privilege escalation rate, escape indicators, and DNS query counts.

### 4. Production Kubernetes & Helm Deployment

For distributed Kubernetes environments, the agent is deployed as a cluster-wide DaemonSet in `kube-system`, alongside a pre-configured Prometheus Operator stack in the `monitoring` namespace.

All manifests are located in `deploy/k8s/`:
* **DaemonSet & Service (`daemonset.yaml`, `service.yaml`)**: Runs the containerized agent with targeted permissions, host networking, host namespaces, and binds to the correct Node IP.
* **Helm Values Override (`prometheus-values.yaml`)**: Overrides `kube-prometheus-stack` to enable cross-namespace `ServiceMonitor` discovery and configures the Grafana sidecar to automatically provision dashboards from ConfigMaps in any namespace.
* **Dashboard ConfigMap (`grafana-dashboard-configmap.yaml`)**: Wraps the 46-panel dashboard JSON in a ConfigMap labeled `grafana_dashboard: "1"` for dynamic hot-loading into Grafana.
* **ServiceMonitor (`servicemonitor.yaml`)**: Targets our agent service in `kube-system` namespace. Uses `honorLabels: true` to prevent Prometheus from stripping the container/pod/namespace labels populated by the eBPF resolver.
* **Ingress (`grafana-ingress.yaml`)**: Configures production access to the Grafana dashboard via an Nginx Ingress Controller.

#### Step-by-Step K8s Deployment
```bash
# 1. Install Prometheus & Grafana stack using custom Helm values
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  -f deploy/k8s/prometheus-values.yaml

# 2. Deploy Dashboard ConfigMap
kubectl apply -f deploy/k8s/grafana-dashboard-configmap.yaml -n monitoring

# 3. Deploy Agent DaemonSet, Service, RBAC, and ServiceAccount
kubectl apply -f deploy/k8s/serviceaccount.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/daemonset.yaml

# 4. Deploy ServiceMonitor (scrapes metrics in kube-system from monitoring)
kubectl apply -f deploy/k8s/servicemonitor.yaml -n monitoring

# 5. Optional: Deploy Ingress rules for external Grafana UI access
kubectl apply -f deploy/k8s/grafana-ingress.yaml
```

#### Accessing the Dashboards
* **Local Port-Forwarding**: `kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80` -> Open `http://localhost:3000` (User: `admin` / Password: dynamic secret. To reset to `admin123` run `kubectl exec -it -n monitoring deploy/prometheus-grafana -c grafana -- grafana-cli admin reset-admin-password admin123`).
* **Minikube Shortcut**: `minikube service prometheus-grafana -n monitoring`
* **Multi-Node Filtering**: The dashboard includes cascading dropdown filters for **Node**, **Namespace**, and **Container** to seamlessly filter telemetry across multi-node topologies.

### 5. AWS EKS Systemd Native Deployment

For VM-based production environments (e.g. AWS EKS worker nodes), we deploy the eBPF Observer agent as a native `systemd` service directly on the host. This guarantees high-performance access to the host kernel namespaces and avoids container capabilities overhead.

We provision the infrastructure using Terraform (`deploy/terraform/`) and manage deployments via `Makefile` targets.

#### Key Features of our EKS Integration:
1. **Local Containerd Metadata Resolver**: Because EKS restricts access to the Kubelet API on port `10250` (returning `403 Forbidden` for standard node IAM roles), the agent bypasses Kubelet completely and walks the local containerd runtime task directory `/run/containerd/io.containerd.runtime.v2.task/k8s.io/` to parse `config.json` files. This extracts Kubernetes container/pod annotations with 100% offline, zero-network, high-speed resolution.
2. **Host-Network Port-Forwarding Tunnel**: Since VMs aren't directly reachable from local scrapers and standard nodes cannot be targeted by `kubectl port-forward`, the `make eks-port-forward` target discovers the `aws-node` VPC CNI pods running on the host network (`hostNetwork: true`). Forwarding to these pods on port `8080` routes traffic directly to the node's loopback network namespace where our agent metrics exporter is listening.
3. **Optimized VM Sizing**: Worker nodes are configured with `t3.small` instances and `20 GB` volumes to comply with EKS AL2023 AMI constraints while staying cost-effective.

#### EKS Management Workflow
```bash
# 1. Initialize and apply Terraform config to spin up EKS & Worker Nodes
cd deploy/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan

# 2. Configure local kubectl context for the new cluster
cd ../..
make eks-kubeconfig

# 3. Compile and upload agent binaries + install script to S3
make eks-push S3_BUCKET=<bucket-name> AWS_REGION=<region>

# 4. Trigger SSM run-command to install & start the systemd service on nodes
make eks-refresh S3_BUCKET=<bucket-name> AWS_REGION=<region>

# 5. Check installation status and systemd logs on EKS nodes
make eks-status

# 6. Start the local port-forwarding metrics scraping tunnel
make eks-port-forward
```

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

## 🛡️ High-Signal Filtering & Audit-Grade Throttling

Observing containerized environments at the kernel level poses a significant challenge: **The Signal-to-Noise Ratio (SNR) is extremely low**. When a Docker container starts up, the container runtime (`runc`) executes **hundreds** of namespace switches, capability checks, and mount operations in less than a second. 

If rendered raw, this massive flood of BPF events:
1. Saturated the TUI viewport and consumed excessive CPU rendering duplicate rows.
2. Immediately pushed critical, low-frequency alerts (like OOM kills) off the screen before the operator could see them.

To solve this, the agent features an **advanced, multi-layered throttling and deduplication engine** designed for high-signal auditing without data loss.

### Core Features & Technical Decisions

* **Container Runtime Noise Filter**: Automatically filters out extremely noisy startup events originating from the container runtime (`runc`). It hides container setup noise while keeping the focus strictly on payload actions.
* **Level 1: Tick-Level Grouping (1-second cycle)**: Within each collection cycle, identical security events inside a container are grouped. If a process attempts 40 privilege-escalation capability checks, the collector compresses them into **exactly one** high-value security event with a `Count` of 40 and updates the timestamp to the latest occurrence.
* **Level 2: Sliding-Window Deduplication (5-second TUI window)**: The TUI Events view scans a rolling 5-second window. Any matching events are dynamically folded into a single row, showing a clear **`(xCount)`** counter next to the styled event badge.
* **Audit-Grade Zero Data Loss**: Unlike naive rate-limiters that drop logs, this count-preserving throttling ensures **100% auditing integrity**. Security operators see a clean, unified UI while retaining the exact count and latest timestamp of every single kernel event!

---

##  Production Incident Journal

### Case Study: Elasticsearch `Max Unsigned32` Thread Counter Overflow

####  Symptom
Highly parallel containerized applications (such as Elasticsearch) sporadically reported exactly **`4,294,967,295`** (`Max uint32` / `0xFFFFFFFF`) live threads in metrics backends, skewing graphs and triggering false pager alerts.

####  Root Cause (eBPF TOCTOU Race Condition)
The BPF program in `ebpf/cpu.c` hooked `sched_process_exit` to decrement a cgroup's live thread count. The original implementation was:
```c
if (s && s->thread_count > 0) {
    __sync_fetch_and_add(&s->thread_count, -1);
}
```
While the decrement instruction `__sync_fetch_and_add` is atomic, the conditional check `s->thread_count > 0` was **not**. Under extreme multithreading concurrency:
1. `thread_count` is `1`.
2. CPU Core A and CPU Core B both evaluate `s->thread_count > 0` as `true` in parallel.
3. Core A decrements the counter to `0`.
4. Core B immediately decrements `0` to `-1`, triggering an **unsigned integer underflow** and wrapping the value to `4,294,967,295`. 

####  BPF Compiler Constraint & Engineering Solution
Older LLVM/clang BPF targets do not support BPF instructions that return the result of an atomic add/sub, throwing an LLVM backend compiler error: `Invalid usage of the XADD return value`.

To solve this safely without using complex loops or losing compatibility, we deployed a **Dual-Shield Counter Guard**:

1. **eBPF-Safe Post-Decrement Guard (Shield 1)**: We removed the non-atomic check and executed a standard BPF-compatible atomic decrement. Immediately following it, we run a post-decrement check:
   ```c
   if (s->thread_count > 0) {
       __sync_fetch_and_add(&s->thread_count, -1);
       // Post-decrement guard: if a race caused underflow, it wraps to max uint32
       if (s->thread_count > 1000000) {
           s->thread_count = 0;
       }
   }
   ```
2. **Go Collector Safety-Net (Shield 2)**: Inside the Go CPU collector ([pkg/collector/cpu.go](file:///media/karim/New%20Volume2/go/ebpf/pkg/collector/cpu.go)), we added a safety-net clamp that resets `ThreadCount` to `0` if it exceeds `1,000,000` (since no normal container reaches 1 million concurrent threads).

### Case Study: Metric & Kernel Memory Leak from Zombie Container Metadata

####  Symptom
When dynamically spawning short-lived containers (e.g. CI/CD runners, job executors), the TUI and Prometheus exporters continued to display dead/zombie containers with `0` CPU, Memory, or Disk usage indefinitely, polluting dashboards and bloating kernel memory usage.

####  Root Cause (Stale BPF Map Accumulation)
1. **BPF Map Persistence**: Although a container's cgroup directory `/sys/fs/cgroup/...` was deleted by the kernel upon termination, the corresponding entries in the BPF maps (such as `cpu_stats_map`, `page_fault_map`, `io_stats_map`, etc.) were never deleted by BPF hooks.
2. **Lookup History Bloat**: The cgroup resolver kept a historical cache (`history`) to handle out-of-order BPF events. However, because this history held container names indefinitely (until a strict 1000-entry limit was reached), Go collectors kept resolving dead cgroup IDs, pulling their stale `0`-usage stats from BPF maps, and presenting them as live.

####  Engineering Solution: Stale Entries Eviction
We implemented a **Stale Entries Eviction system** that manages deletion at both the userspace and kernel-space level:

1. **TTL-Driven Deletion (Go Goroutine)**:
   Inside the cgroup `Resolver` ([pkg/cgroup/resolver.go](file:///media/karim/New%20Volume2/go/ebpf/pkg/cgroup/resolver.go)), we added a `deletedAt` map tracking when cgroups are unlinked. A dedicated background eviction goroutine runs every 5 seconds and evicts any metadata from `history` that has been dead for more than **2 refresh cycles (20 seconds)**.
2. **BPF Map Kernel Pruning**:
   Inside each of our 5 metric collectors, during map iteration, we check if the cgroup ID is still active. If the cgroup resolver returns `ok = false` (meaning the cgroup is dead and its TTL in history has expired), the collector **immediately deletes** the entry from the kernel BPF map:
   * **CPU**: deletes key from `cpu_stats_map`.
   * **Memory**: deletes key from `page_fault_map`.
   * **Disk I/O**: deletes key from `io_stats_map`.
   * **Network**: deletes key from `conn_stats_map`.
   * **Syscalls**: deletes key from `statsMap`.

This instantly stops the metric leak, reduces userspace iteration overhead, and cleans up kernel memory!

### Case Study: Prometheus Target Scrape Label Conflicts (Stale `ebpf-observer` Container Label)

#### Symptom
After deploying the observability agent into a Kubernetes cluster, all container metrics on the Grafana dashboard displayed with the container name `ebpf-observer` (the name of our agent pod) rather than the actual namespace/pod/container names of the workloads.

#### Root Cause
By default, when Prometheus scrapes a target (our agent's `/metrics` endpoint), it overrides metric-level metadata labels like `container`, `pod`, and `namespace` with the target's own labels (the agent's metadata). To prevent data loss, it renames the metric's original values to `exported_container`, `exported_pod`, etc.

#### Engineering Solution
We applied two configurations to resolve this:
1. Enabled **`honorLabels: true`** in our `ServiceMonitor` ([deploy/k8s/servicemonitor.yaml](file:///media/karim/New%20Volume2/go/ebpf/deploy/k8s/servicemonitor.yaml)). This instructs Prometheus to trust the labels resolved by our eBPF agent and prevent overriding them.
2. Filtered out Kubernetes infrastructure **Pause containers** (`registry.k8s.io/pause`), which manage network namespaces but do not run user code and aren't listed in the Kubelet `/pods` API. These fall back to standard `docker:<short-id>` labels to preserve transparency.

### Case Study: eBPF Map Iterator Collapse (Syscall Metrics Black Hole)

#### Symptom
Syscall and CPU metrics sporadically vanished from the Grafana dashboard, and the agent's container logs repeatedly reported `iteration aborted` errors:
```text
level=ERROR msg="Syscall collect error" err="iteration aborted"
level=ERROR msg="CPU collect error" err="iterating cpu_stats_map: iteration aborted"
```

#### Root Cause (Iterator Offset Corruption)
Inside the `Collect()` loop of all BPF collectors, we iterated over BPF maps using the `Map.Iterate().Next()` API. If a container was determined to be dead/exited, the code immediately invoked `Map.Delete(&key)` from within the loop. In the Linux kernel, modifying a hash map (deleting keys) while active iteration is in progress corrupts the iterator's internal bucket offset, causing it to fail immediately and abort metric retrieval.

#### Engineering Solution
We restructured the map traversal pattern across all 5 collectors (CPU, Memory, I/O, Network, and Syscalls) to use a **Deferred Eviction Pattern**:
1. Iterate over the BPF map to read metrics and identify stale keys, adding them to a slice (e.g. `toDelete := []Key{}`).
2. Exit the map iteration loop cleanly.
3. Perform the map deletions sequentially in a separate loop:
   ```go
   for _, key := range toDelete {
       _ = c.statsMap.Delete(&key)
   }
   ```
This guarantees that BPF map iteration is never interrupted, ensuring stable metric streams and preventing collection black holes.

### Case Study: EKS Kubelet API 403 Forbidden & Local Containerd Resolver Transition

#### Symptom
After deploying the observability agent to EKS worker nodes, all container names in Grafana, Prometheus metrics, and the exporter output displayed as cgroup ID hashes (e.g. `k8s:be00f518575c` or `k8s:d28ba543ebcb`) instead of human-readable `namespace/pod/container` names.

#### Root Cause
1. **Strict Kubelet API Port 10250 Authentication**: EKS disables anonymous authentication to the Kubelet on port `10250` and disables the read-only port `10255` entirely.
2. **IAM Authorization Denials (HTTP 403 Forbidden)**: Although the agent ran as `root`, it did not have a service account token mounted. When it generated an EKS token using the node's IAM role (`system:node:ip-...`), the Kubernetes API server rejected the Kubelet proxy request with `403 Forbidden`. The node role is restricted to self-registration and cannot read pod configurations from Kubelet.
3. **Sandbox Container Skips**: The initial implementation skipped container configs flagged as `sandbox` (pause containers), leaving their metrics unresolved.

#### Engineering Solution
We implemented a **Local Containerd OCI Runtime Config Resolver** as the primary resolution path:
1. **Task Directory Walk**: Since the agent runs as `root` on the host, it scans the local containerd task directory: `/run/containerd/io.containerd.runtime.v2.task/k8s.io/`.
2. **OCI Spec Parsing**: It reads each active container's `config.json` and extracts the Kubernetes-populated annotations directly from the OCI spec:
   * `io.kubernetes.cri.sandbox-name` (Pod Name)
   * `io.kubernetes.cri.sandbox-namespace` (Namespace)
   * `io.kubernetes.cri.container-name` (Container Name)
3. **Sandbox Handling**: If a task is a sandbox (pause container), it is named `sandbox` (resolving to `namespace/pod/sandbox`) instead of being skipped.
This provides 100% offline, zero-dependency, and extremely fast metadata resolution that is completely decoupled from API server access.

---

## Themes

Press `T` to cycle through 6 built-in themes:

`github-dark` · `nord` · `gruvbox` · `tokyo-night` · `catppuccin` · `solarized`

---

## License

eBPF C programs are licensed under **GPL-2.0** (required for kernel access).  
Go agent code is available under the same license.
