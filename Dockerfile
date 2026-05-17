# syntax=docker/dockerfile:1

# Builder stage
FROM ubuntu:22.04 AS builder

# Avoid timezone interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for eBPF and Go compilation
RUN apt-get update && apt-get install -y \
    wget \
    make \
    clang \
    llvm \
    libbpf-dev \
    gcc \
    linux-headers-generic

# Install Go 1.22 (matching go.mod roughly, or latest stable)
WORKDIR /tmp
RUN wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /app

# Download dependencies first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Compile eBPF programs AOT
RUN make bpf

# Build static Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o observer ./cmd/observer

# Final runtime stage
FROM ubuntu:22.04

# Install minimal debugging utilities
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled static binary
COPY --from=builder /app/observer /app/

# Copy precompiled eBPF object files
RUN mkdir -p /app/ebpf
COPY --from=builder /app/ebpf/*.o /app/ebpf/

# Expose metrics/health port
EXPOSE 8080

# Run observer with both performance and security modules enabled
ENTRYPOINT ["/app/observer"]
CMD ["--cpu-bpf", "/app/ebpf/cpu.o", \
     "--mem-bpf", "/app/ebpf/memory.o", \
     "--io-bpf", "/app/ebpf/io.o", \
     "--net-bpf", "/app/ebpf/network.o", \
     "--sys-bpf", "/app/ebpf/syscall.o", \
     "--lineage-bpf", "/app/ebpf/lineage.o", \
     "--exec-bpf", "/app/ebpf/exec.o", \
     "--dns-bpf", "/app/ebpf/dns.o", \
     "--privesc-bpf", "/app/ebpf/privesc.o", \
     "--escape-bpf", "/app/ebpf/escape.o", \
     "--containers-only", \
     "--show-security"]
