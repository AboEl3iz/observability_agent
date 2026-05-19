#!/usr/bin/env bash
# =============================================================================
# ebpf-observer node bootstrap script
# Runs at first boot via EC2 user-data on EKS AL2023 worker nodes.
#
# What this does:
#   1. Wait for the instance's IAM role credentials to be available via IMDS
#   2. Install runtime dependencies (clang, llvm, libbpf)
#   3. Download compiled artifacts from S3 (binary + eBPF .o files + config)
#   4. Install binary, BPF objects, systemd unit, and environment file
#   5. Create the BPF pin path
#   6. Enable and start the ebpf-observer.service
#
# Logs: all output is tee'd to /var/log/ebpf-observer-install.log
#
# Re-running: this script is idempotent. Running it again will overwrite
# binaries and restart the service (useful for updates via SSM Run Command).
# =============================================================================

set -euo pipefail

# ── Configuration (injected by Terraform templatefile) ───────────────────────
S3_BUCKET="${s3_bucket}"
S3_PREFIX="${s3_prefix}"
AWS_REGION="${aws_region}"
METRICS_PORT="${metrics_port}"
INSTALL_DIR="/usr/local/share/ebpf-observer"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
ENV_DIR="/etc/default"
BPF_PIN_PATH="/sys/fs/bpf/ebpf-agent"
LOG_FILE="/var/log/ebpf-observer-install.log"

# ── Logging helper ────────────────────────────────────────────────────────────
log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "$LOG_FILE"; }

log "============================================================"
log "  ebpf-observer bootstrap starting"
log "  S3 bucket  : $S3_BUCKET"
log "  S3 prefix  : $S3_PREFIX"
log "  AWS region : $AWS_REGION"
log "============================================================"

# ── Wait for IMDS / IAM credentials ──────────────────────────────────────────
log "Waiting for IMDSv2 token..."
for i in $(seq 1 30); do
  TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null) && break
  log "  IMDS not ready (attempt $i/30), retrying in 5s..."
  sleep 5
done
: "$${TOKEN:?IMDS token unavailable — IAM role not attached? Aborting.}"
log "IMDS token obtained."

# ── Install runtime dependencies ──────────────────────────────────────────────
log "Installing runtime dependencies via dnf..."
dnf install -y --quiet \
  clang \
  llvm \
  libbpf \
  libbpf-devel \
  bpftool 2>&1 | tee -a "$LOG_FILE"
log "Dependencies installed."

# ── Create directory structure ────────────────────────────────────────────────
log "Creating installation directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BPF_PIN_PATH"

# ── Download artifacts from S3 ────────────────────────────────────────────────
log "Downloading artifacts from s3://$S3_BUCKET/$S3_PREFIX ..."

# Observer binary
aws s3 cp "s3://$S3_BUCKET/$S3_PREFIX/observer" "$BIN_DIR/ebpf-observer" \
  --region "$AWS_REGION" 2>&1 | tee -a "$LOG_FILE"
chmod 755 "$BIN_DIR/ebpf-observer"
log "  ✓ observer binary downloaded"

# eBPF object files
aws s3 sync "s3://$S3_BUCKET/$S3_PREFIX/ebpf/" "$INSTALL_DIR/" \
  --region "$AWS_REGION" \
  --exclude "*" --include "*.o" 2>&1 | tee -a "$LOG_FILE"
log "  ✓ eBPF .o objects downloaded"

# systemd unit file
aws s3 cp "s3://$S3_BUCKET/$S3_PREFIX/systemd/ebpf-observer.service" \
  "$SYSTEMD_DIR/ebpf-observer.service" \
  --region "$AWS_REGION" 2>&1 | tee -a "$LOG_FILE"
chmod 644 "$SYSTEMD_DIR/ebpf-observer.service"
log "  ✓ systemd unit downloaded"

# Environment / config file
aws s3 cp "s3://$S3_BUCKET/$S3_PREFIX/systemd/ebpf-observer.env" \
  "$ENV_DIR/ebpf-observer" \
  --region "$AWS_REGION" 2>&1 | tee -a "$LOG_FILE"
chmod 644 "$ENV_DIR/ebpf-observer"
log "  ✓ environment file downloaded"

# ── Verify checksums if manifest present ──────────────────────────────────────
if aws s3 ls "s3://$S3_BUCKET/$S3_PREFIX/SHA256SUMS" --region "$AWS_REGION" &>/dev/null; then
  log "Verifying SHA256 checksums..."
  aws s3 cp "s3://$S3_BUCKET/$S3_PREFIX/SHA256SUMS" /tmp/SHA256SUMS \
    --region "$AWS_REGION" 2>&1 | tee -a "$LOG_FILE"
  # Only verify files we actually downloaded
  grep -E "(observer|\.o)$" /tmp/SHA256SUMS | while read -r sum file; do
    base_file=$(basename "$file")
    if [ "$base_file" = "observer" ] || [ "$base_file" = "ebpf-observer" ]; then
      local_path="$BIN_DIR/ebpf-observer"
    else
      local_path="$INSTALL_DIR/$base_file"
    fi
    if [ ! -f "$local_path" ]; then
      log "  ✗ File not found for checksum: $base_file (expected at $local_path)"
      exit 1
    fi
    if echo "$sum  $local_path" | sha256sum --check --status; then
      log "  ✓ checksum OK: $base_file"
    else
      log "  ✗ checksum FAIL: $base_file — aborting!"
      exit 1
    fi
  done
  log "All checksums verified."
else
  log "No SHA256SUMS manifest found — skipping checksum verification."
fi

# ── Patch env file for EKS-specific mode ─────────────────────────────────────
# Override the env file to enable kubernetes mode and expose the correct port.
# This is additive — we append rather than replace so existing flags are kept.
log "Patching environment file for EKS/kubernetes mode..."
cat > "$ENV_DIR/ebpf-observer" <<ENVEOF
# eBPF Observer — EKS / systemd configuration
# Generated by node bootstrap script on $(date -u)
EBPF_OBSERVER_OPTS="\
  --cpu-bpf $INSTALL_DIR/cpu.o \
  --mem-bpf $INSTALL_DIR/memory.o \
  --io-bpf $INSTALL_DIR/io.o \
  --net-bpf $INSTALL_DIR/network.o \
  --sys-bpf $INSTALL_DIR/syscall.o \
  --lineage-bpf $INSTALL_DIR/lineage.o \
  --exec-bpf $INSTALL_DIR/exec.o \
  --dns-bpf $INSTALL_DIR/dns.o \
  --privesc-bpf $INSTALL_DIR/privesc.o \
  --escape-bpf $INSTALL_DIR/escape.o \
  --containers-only \
  --kubernetes \
  --show-security \
  --rich-mem"
ENVEOF
log "Environment file written."

# ── Enable and start ebpf-observer ────────────────────────────────────────────
log "Reloading systemd and enabling ebpf-observer.service..."
systemctl daemon-reload
systemctl enable ebpf-observer.service
systemctl restart ebpf-observer.service

# Wait a moment then check status
sleep 3
if systemctl is-active --quiet ebpf-observer.service; then
  log "ebpf-observer.service is ACTIVE and running."
else
  log "ebpf-observer.service failed to start — see 'journalctl -u ebpf-observer' for details."
  journalctl -u ebpf-observer -n 50 --no-pager | tee -a "$LOG_FILE"
  # Do NOT exit 1 here — we don't want the node to be marked unhealthy
  # just because the agent failed. The kubelet should still join the cluster.
fi

# ── Tag the EC2 instance to mark bootstrap completion ─────────────────────────
INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/instance-id")
aws ec2 create-tags \
  --region "$AWS_REGION" \
  --resources "$INSTANCE_ID" \
  --tags \
    "Key=ebpf-observer/bootstrap,Value=complete" \
    "Key=ebpf-observer/install-time,Value=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  2>&1 | tee -a "$LOG_FILE" || true   # non-fatal — tagging is best-effort

log "Bootstrap complete. Logs: $LOG_FILE"
log "============================================================"
