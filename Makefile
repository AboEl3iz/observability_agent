BPF_CLANG     := clang
BPF_CFLAGS    := -O2 -g -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -D__TARGET_ARCH_x86

GO            := go
BINARY        := observer
ENTRY         := ./cmd/observer
TUI_BINARY    := tui
TUI_ENTRY     := ./cmd/tui

# ─── BPF objects ──────────────────────────────────────────────────────────────
BPF_SRC_CPU    := ebpf/cpu.c
BPF_OBJ_CPU    := ebpf/cpu.o

BPF_SRC_MEM    := ebpf/memory.c
BPF_OBJ_MEM    := ebpf/memory.o

BPF_SRC_IO     := ebpf/io.c
BPF_OBJ_IO     := ebpf/io.o

BPF_SRC_NET    := ebpf/network.c
BPF_OBJ_NET    := ebpf/network.o

BPF_SRC_SYS    := ebpf/syscall.c
BPF_OBJ_SYS    := ebpf/syscall.o

# Legacy program (kept for reference)
BPF_SRC_PROG  := ebpf/program.c
BPF_OBJ_PROG  := ebpf/program.o


.PHONY: all build bpf go-build test run run-all run-cpu-only run-files run-tui run-tui-demo clean docker-build docker-run

all: build

# ─── BPF compilation ──────────────────────────────────────────────────────────
bpf: $(BPF_OBJ_CPU) $(BPF_OBJ_MEM) $(BPF_OBJ_IO) $(BPF_OBJ_NET) $(BPF_OBJ_SYS)

$(BPF_OBJ_CPU): $(BPF_SRC_CPU)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ M1 CPU BPF object compiled: $@"

$(BPF_OBJ_MEM): $(BPF_SRC_MEM)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ M2 Memory BPF object compiled: $@"

$(BPF_OBJ_IO): $(BPF_SRC_IO)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ M3 I/O BPF object compiled: $@"

$(BPF_OBJ_NET): $(BPF_SRC_NET)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ M4 Network BPF object compiled: $@"

$(BPF_OBJ_PROG): $(BPF_SRC_PROG)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_OBJ_SYS): $(BPF_SRC_SYS)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ M6 Syscall BPF object compiled: $@"


# ─── Go build ─────────────────────────────────────────────────────────────────
go-build:
	$(GO) mod tidy
	$(GO) build -o $(BINARY) $(ENTRY)

build: bpf go-build
	@echo "✅ Full build complete: M1+M2+M3+M4+M6 BPF + Go binary"

# ─── Tests (no BPF / no root required) ───────────────────────────────────────
test:
	$(GO) test -v -count=1 ./pkg/...

# ─── Run (requires root + cgroup v2) ─────────────────────────────────────────
# Default: show Docker/containerd containers only (filters out host cgroups)
run: build
	sudo ./$(BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS) \
		--containers-only

# Show all cgroups (host processes, systemd slices, containers)
run-all: build
	sudo ./$(BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS)

# Run M1 only (CPU, containers only)
run-cpu-only: $(BPF_OBJ_CPU) go-build
	sudo ./$(BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf /dev/null \
		--io-bpf  /dev/null \
		--net-bpf /dev/null \
		--sys-bpf /dev/null \
		--containers-only

# Stream file open events and TCP transitions (containers only)
run-files: build
	sudo ./$(BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS) \
		--containers-only \
		--show-files \
		--show-tcp \
		--show-slow-sys

# ─── TUI targets ─────────────────────────────────────────────────────────────
tui-build: bpf
	$(GO) build -o $(TUI_BINARY) $(TUI_ENTRY)

# Full TUI with BPF (containers only, TCP + file events streamed)
run-tui: tui-build
	sudo ./$(TUI_BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS) \
		--containers-only \
		--show-tcp \
		--show-files \
		--show-slow-sys

# Demo TUI — no BPF, no root required; containers-only filters host cgroups
run-tui-demo:
	$(GO) run $(TUI_ENTRY) --demo

run-tui-demo-filtered:
	$(GO) run $(TUI_ENTRY) --demo --containers-only

# ─── Cleanup ──────────────────────────────────────────────────────────────────
clean:
	rm -f ebpf/*.o $(BINARY) $(TUI_BINARY)

# ─── Docker targets ───────────────────────────────────────────────────────────
docker-build:
	docker build -t ebpf_observer:latest .

docker-run:
	docker-compose up -d