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

# Phase 1–5: Security telemetry
BPF_SRC_LINEAGE  := ebpf/lineage.c
BPF_OBJ_LINEAGE  := ebpf/lineage.o

BPF_SRC_EXEC     := ebpf/exec.c
BPF_OBJ_EXEC     := ebpf/exec.o

BPF_SRC_DNS      := ebpf/dns.c
BPF_OBJ_DNS      := ebpf/dns.o

BPF_SRC_PRIVESC  := ebpf/privesc.c
BPF_OBJ_PRIVESC  := ebpf/privesc.o

BPF_SRC_ESCAPE   := ebpf/escape.c
BPF_OBJ_ESCAPE   := ebpf/escape.o

# BPF pin path for cross-module map sharing
BPF_PIN_PATH     := /sys/fs/bpf/ebpf-agent

# Legacy program (kept for reference)
BPF_SRC_PROG  := ebpf/program.c
BPF_OBJ_PROG  := ebpf/program.o


.PHONY: all build bpf go-build test run run-k8s run-all run-cpu-only run-files run-security run-tui run-tui-demo clean docker-build docker-run pin-path monitoring-up monitoring-down monitoring-logs monitoring-prom-only install uninstall systemd-start systemd-stop systemd-status systemd-logs eks-push eks-kubeconfig eks-port-forward eks-status eks-logs eks-refresh eks-destroy


all: build

# ─── BPF compilation ──────────────────────────────────────────────────────────
bpf: $(BPF_OBJ_CPU) $(BPF_OBJ_MEM) $(BPF_OBJ_IO) $(BPF_OBJ_NET) $(BPF_OBJ_SYS) \
     $(BPF_OBJ_LINEAGE) $(BPF_OBJ_EXEC) $(BPF_OBJ_DNS) $(BPF_OBJ_PRIVESC) $(BPF_OBJ_ESCAPE)

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

$(BPF_OBJ_LINEAGE): $(BPF_SRC_LINEAGE)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ Phase 1 Lineage BPF object compiled: $@"

$(BPF_OBJ_EXEC): $(BPF_SRC_EXEC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ Phase 2 Exec BPF object compiled: $@"

$(BPF_OBJ_DNS): $(BPF_SRC_DNS)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ Phase 3 DNS BPF object compiled: $@"

$(BPF_OBJ_PRIVESC): $(BPF_SRC_PRIVESC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ Phase 4 PrivEsc BPF object compiled: $@"

$(BPF_OBJ_ESCAPE): $(BPF_SRC_ESCAPE)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✅ Phase 5 Escape BPF object compiled: $@"

# Ensure BPF pin path exists (must be run as root before agent starts)
pin-path:
	@mkdir -p $(BPF_PIN_PATH)
	@echo "✅ BPF pin path created: $(BPF_PIN_PATH)"


# ─── Go build ─────────────────────────────────────────────────────────────────
go-build:
	$(GO) mod tidy
	$(GO) build -o $(BINARY) $(ENTRY)

build: bpf go-build
	@echo "✅ Full build complete: M1+M2+M3+M4+M6 + Phase1-5 Security BPF + Go binary"

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
		--containers-only \
		--rich-mem

# Run in Kubernetes mode
run-k8s: build
	sudo mkdir -p $(BPF_PIN_PATH)
	sudo ./$(BINARY) \
		--cpu-bpf     $(BPF_OBJ_CPU) \
		--mem-bpf     $(BPF_OBJ_MEM) \
		--io-bpf      $(BPF_OBJ_IO) \
		--net-bpf     $(BPF_OBJ_NET) \
		--sys-bpf     $(BPF_OBJ_SYS) \
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--containers-only \
		--kubernetes \
		--show-security \
		--rich-mem

# Show all cgroups (host processes, systemd slices, containers)
run-all: build
	sudo ./$(BINARY) \
		--cpu-bpf $(BPF_OBJ_CPU) \
		--mem-bpf $(BPF_OBJ_MEM) \
		--io-bpf  $(BPF_OBJ_IO) \
		--net-bpf $(BPF_OBJ_NET) \
		--sys-bpf $(BPF_OBJ_SYS) \
		--rich-mem

# Security telemetry mode: all 5 phases + show-security events on stderr
run-security: build
	sudo mkdir -p $(BPF_PIN_PATH)
	sudo ./$(BINARY) \
		--cpu-bpf     $(BPF_OBJ_CPU) \
		--mem-bpf     $(BPF_OBJ_MEM) \
		--io-bpf      $(BPF_OBJ_IO) \
		--net-bpf     $(BPF_OBJ_NET) \
		--sys-bpf     $(BPF_OBJ_SYS) \
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--containers-only \
		--show-security \
		--rich-mem

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
		--show-slow-sys \
		--rich-mem

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
		--lineage-bpf $(BPF_OBJ_LINEAGE) \
		--exec-bpf    $(BPF_OBJ_EXEC) \
		--dns-bpf     $(BPF_OBJ_DNS) \
		--privesc-bpf $(BPF_OBJ_PRIVESC) \
		--escape-bpf  $(BPF_OBJ_ESCAPE) \
		--containers-only \
		--rich-mem

# Demo TUI — no BPF, no root required; containers-only filters host cgroups
run-tui-demo:
	$(GO) run $(TUI_ENTRY) --demo

run-tui-demo-filtered:
	$(GO) run $(TUI_ENTRY) --demo --containers-only

# ─── Cleanup ──────────────────────────────────────────────────────────────────
clean:
	rm -f ebpf/*.o $(BINARY) $(TUI_BINARY)
	@# Remove pinned BPF maps (requires root)
	@sudo rm -rf $(BPF_PIN_PATH) 2>/dev/null || true

# ─── Docker targets ───────────────────────────────────────────────────────────
docker-build:
	docker build -t ebpf-observer:latest .

docker-run:
	docker-compose up -d ebpf-observer

# ─── Monitoring stack (Prometheus + Grafana) ─────────────────────────────────
# Start full observability stack: eBPF agent + Prometheus + Grafana
monitoring-up: docker-build
	docker compose up -d
	@echo ""
	@echo " Monitoring stack started:"
	@echo "   eBPF Observer  → http://localhost:8080/metrics"
	@echo "   Prometheus     → http://localhost:9090"
	@echo "   Grafana        → http://localhost:3000  (admin/admin)"
	@echo ""
	@echo "   Run: make monitoring-logs   to tail observer logs"
	@echo "   Run: make monitoring-down   to stop everything"

# Stop the monitoring stack
monitoring-down:
	docker-compose down

# Tail agent logs
monitoring-logs:
	docker-compose logs -f ebpf-observer

# Prometheus only (faster for CI/testing)
monitoring-prom-only: docker-build
	docker-compose up -d ebpf-observer prometheus
	@echo " Prometheus scraping at http://localhost:9090"

# ─── Kubernetes & Minikube targets ───────────────────────────────────────────
k8s-deploy: docker-build
	@echo "Loading Docker image into minikube..."
	minikube image load ebpf-observer:latest || true
	@echo "Installing/upgrading Prometheus Operator Helm stack..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	helm repo update
	helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
		--namespace monitoring --create-namespace \
		-f deploy/k8s/prometheus-values.yaml
	@echo "Deploying Grafana Dashboard ConfigMap..."
	kubectl apply -f deploy/k8s/grafana-dashboard-configmap.yaml -n monitoring
	@echo "Deploying Agent DaemonSet, Service, and RBAC..."
	kubectl apply -f deploy/k8s/serviceaccount.yaml
	kubectl apply -f deploy/k8s/rbac.yaml
	kubectl apply -f deploy/k8s/service.yaml
	kubectl apply -f deploy/k8s/daemonset.yaml
	@echo "Deploying ServiceMonitor..."
	kubectl apply -f deploy/k8s/servicemonitor.yaml -n monitoring
	@echo "Deploying Ingress..."
	kubectl apply -f deploy/k8s/grafana-ingress.yaml
	@echo " Kubernetes deployment completed!"

k8s-undeploy:
	@echo "Removing Agent manifests..."
	-kubectl delete -f deploy/k8s/grafana-ingress.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/servicemonitor.yaml -n monitoring 2>/dev/null || true
	-kubectl delete -f deploy/k8s/daemonset.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/service.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/rbac.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/serviceaccount.yaml 2>/dev/null || true
	-kubectl delete -f deploy/k8s/grafana-dashboard-configmap.yaml -n monitoring 2>/dev/null || true
	@echo "Uninstalling Helm release..."
	-helm uninstall prometheus -n monitoring 2>/dev/null || true
	@echo " Kubernetes deployment removed!"

k8s-restart: docker-build
	@echo "Loading Docker image into minikube..."
	minikube image load ebpf-observer:latest
	@echo "Rolling out restart of eBPF Observer DaemonSet..."
	kubectl rollout restart daemonset ebpf-observer -n kube-system
	kubectl rollout status daemonset ebpf-observer -n kube-system

k8s-dashboard:
	@echo "------------------------------------------------------------"
	@echo " Grafana Credentials:"
	@echo "   Username: admin"
	@echo "   Password: $$(kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath='{.data.admin-password}' | base64 --decode)"
	@echo "------------------------------------------------------------"
	@echo " Port-forwarding Grafana to http://localhost:3000..."
	kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80

# ─── EKS / S3 Targets ────────────────────────────────────────────────────────
#
# Prerequisites:
#   - AWS CLI configured  (aws sts get-caller-identity  must work)
#   - Terraform applied   (cd deploy/terraform && terraform apply)
#   - kubectl configured  (make eks-kubeconfig)
#
# Workflow:
#   1. make eks-kubeconfig      → configure kubectl
#   2. make eks-push            → build + upload to S3
#   3. make eks-refresh         → (re-)run install on nodes via SSM
#   4. make eks-port-forward    → background port-forward
#   5. make monitoring-up       → start local Prometheus + Grafana
#   6. make eks-destroy         → tear everything down when done

TF_DIR         := deploy/terraform
AWS_REGION     ?= us-east-1
S3_BUCKET      ?= $(shell cd $(TF_DIR) && terraform output -raw s3_bucket_name 2>/dev/null || echo "")
CLUSTER_NAME   ?= $(shell cd $(TF_DIR) && terraform output -raw cluster_name 2>/dev/null || echo "ebpf-observer-test")
S3_PREFIX      := releases/latest
SHA256SUMS     := SHA256SUMS

# Build, checksum, and upload artifacts to S3
eks-push: build
	@if [ -z "$(S3_BUCKET)" ]; then \
	  echo " S3_BUCKET not set. Run 'cd deploy/terraform && terraform apply' first."; exit 1; fi
	@echo " Generating SHA256SUMS..."
	@sha256sum $(BINARY) ebpf/*.o deploy/systemd/ebpf-observer.service deploy/systemd/ebpf-observer.env \
	  > /tmp/$(SHA256SUMS)
	@echo "Uploading artifacts to s3://$(S3_BUCKET)/$(S3_PREFIX)/"
	aws s3 cp $(BINARY) \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/observer \
	  --region $(AWS_REGION) --sse AES256
	aws s3 sync ebpf/ \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/ebpf/ \
	  --region $(AWS_REGION) --sse AES256 \
	  --exclude "*" --include "*.o"
	aws s3 sync deploy/systemd/ \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/systemd/ \
	  --region $(AWS_REGION) --sse AES256
	aws s3 cp deploy/terraform/userdata/install.sh \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/userdata/install.sh \
	  --region $(AWS_REGION) --sse AES256
	aws s3 cp /tmp/$(SHA256SUMS) \
	  s3://$(S3_BUCKET)/$(S3_PREFIX)/$(SHA256SUMS) \
	  --region $(AWS_REGION) --sse AES256
	@echo ""
	@echo " Artifacts uploaded to s3://$(S3_BUCKET)/$(S3_PREFIX)/"
	@echo "   Run 'make eks-refresh' to re-install on running nodes."

# Configure kubectl to talk to the EKS cluster
eks-kubeconfig:
	@echo "Updating kubeconfig for cluster: $(CLUSTER_NAME)"
	aws eks update-kubeconfig --region $(AWS_REGION) --name $(CLUSTER_NAME)
	@echo " kubectl configured. Test with: kubectl get nodes"

# Port-forward both nodes' metrics endpoints to local ports 8081 and 8082.
# Run in a dedicated terminal — keep it open while using local Prometheus.
eks-port-forward:
	@echo "Identifying worker nodes and host-network pods..."
	@PODS=$$(kubectl get pods -n kube-system -l k8s-app=aws-node -o jsonpath='{.items[*].metadata.name}'); \
	METRICS_PORT=8080; \
	LOCAL_PORT=8081; \
	PIDS=""; \
	for POD in $$PODS; do \
	  NODE=$$(kubectl get pod -n kube-system $$POD -o jsonpath='{.spec.nodeName}'); \
	  echo "  Port-forwarding $$NODE (via pod $$POD) → localhost:$$LOCAL_PORT"; \
	  kubectl port-forward -n kube-system $$POD $$LOCAL_PORT:$$METRICS_PORT & \
	  PIDS="$$PIDS $$!"; \
	  LOCAL_PORT=$$((LOCAL_PORT + 1)); \
	done; \
	echo ""; \
	echo " Port-forward active. Press Ctrl-C to stop."; \
	echo "   Node metrics: http://localhost:8081/metrics  http://localhost:8082/metrics"; \
	trap 'kill $$PIDS 2>/dev/null' INT TERM; \
	wait $$PIDS

# Check ebpf-observer systemd status on all nodes via SSM Run Command
eks-status:
	@echo "Checking ebpf-observer status on all EKS nodes (via SSM)..."
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "── Node: $$ID ───────────────────────────────────────────"; \
	  CMD_ID=$$(aws ssm send-command \
	    --region $(AWS_REGION) \
	    --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters 'commands=["systemctl status ebpf-observer --no-pager -l","echo ---INSTALL-LOG---","tail -20 /var/log/ebpf-observer-install.log 2>/dev/null"]' \
	    --query 'Command.CommandId' --output text); \
	  sleep 5; \
	  aws ssm get-command-invocation \
	    --region $(AWS_REGION) \
	    --command-id $$CMD_ID \
	    --instance-id $$ID \
	    --query 'StandardOutputContent' --output text; \
	done

# Tail journald logs from all nodes via SSM
eks-logs:
	@echo "Fetching last 100 lines of ebpf-observer journal from all EKS nodes..."
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "── Node: $$ID logs ─────────────────────────────────────"; \
	  CMD_ID=$$(aws ssm send-command \
	    --region $(AWS_REGION) \
	    --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters 'commands=["journalctl -u ebpf-observer -n 100 --no-pager"]' \
	    --query 'Command.CommandId' --output text); \
	  sleep 5; \
	  aws ssm get-command-invocation \
	    --region $(AWS_REGION) \
	    --command-id $$CMD_ID \
	    --instance-id $$ID \
	    --query 'StandardOutputContent' --output text; \
	done

# Trigger a re-install of ebpf-observer on all running nodes via SSM.
# Use after 'make eks-push' to apply updated artifacts without recycling nodes.
eks-refresh:
	@if [ -z "$(S3_BUCKET)" ]; then \
	  echo " S3_BUCKET not set. Run 'cd deploy/terraform && terraform apply' first."; exit 1; fi
	@echo "Re-installing ebpf-observer on all EKS nodes via SSM..."
	@INSTANCES=$$(aws ec2 describe-instances \
	  --region $(AWS_REGION) \
	  --filters \
	    "Name=tag:kubernetes.io/cluster/$(CLUSTER_NAME),Values=owned" \
	    "Name=instance-state-name,Values=running" \
	  --query 'Reservations[].Instances[].InstanceId' \
	  --output text); \
	for ID in $$INSTANCES; do \
	  echo "  Refreshing node $$ID ..."; \
	  aws ssm send-command \
	    --region $(AWS_REGION) \
	    --instance-ids $$ID \
	    --document-name AWS-RunShellScript \
	    --parameters "commands=[\
	      \"set -e\",\
	      \"aws s3 cp s3://$(S3_BUCKET)/$(S3_PREFIX)/observer /usr/local/bin/ebpf-observer --region $(AWS_REGION) --sse AES256\",\
	      \"chmod 755 /usr/local/bin/ebpf-observer\",\
	      \"aws s3 sync s3://$(S3_BUCKET)/$(S3_PREFIX)/ebpf/ /usr/local/share/ebpf-observer/ --region $(AWS_REGION) --exclude '*' --include '*.o'\",\
	      \"systemctl daemon-reload\",\
	      \"systemctl restart ebpf-observer\",\
	      \"sleep 3\",\
	      \"systemctl is-active ebpf-observer && echo OK || echo FAILED\"\
	    ]" \
	    --query 'Command.CommandId' --output text; \
	  echo "  SSM command dispatched for $$ID"; \
	done
	@echo ""
	@echo " Refresh commands dispatched. Check status with: make eks-status"

# Destroy all EKS infrastructure (stops all charges)
eks-destroy:
	@echo " This will DESTROY the EKS cluster, nodes, VPC, and S3 bucket."
	@read -p "Type 'yes' to confirm: " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
	  cd $(TF_DIR) && terraform destroy; \
	  echo " All infrastructure destroyed — no more charges."; \
	else \
	  echo "Aborted."; \
	fi

# ─── Systemd Native Installation ──────────────────────────────────────────────
INSTALL_DIR     := /usr/local/share/ebpf-observer
BIN_DIR         := /usr/local/bin
SYSTEMD_DIR     := /etc/systemd/system
ENV_DIR         := /etc/default

install: build
	@echo "Installing native ebpf-observer..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(BINARY) $(BIN_DIR)/ebpf-observer
	sudo cp ebpf/*.o $(INSTALL_DIR)/
	sudo cp deploy/systemd/ebpf-observer.service $(SYSTEMD_DIR)/
	sudo cp deploy/systemd/ebpf-observer.env $(ENV_DIR)/ebpf-observer
	sudo chmod 644 $(SYSTEMD_DIR)/ebpf-observer.service
	sudo chmod 644 $(ENV_DIR)/ebpf-observer
	sudo chmod 755 $(BIN_DIR)/ebpf-observer
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-observer
	@echo " Installation complete! You can start the service with:"
	@echo "   sudo systemctl start ebpf-observer"

uninstall:
	@echo "Stopping and disabling ebpf-observer systemd service..."
	-sudo systemctl stop ebpf-observer
	-sudo systemctl disable ebpf-observer
	sudo rm -f $(SYSTEMD_DIR)/ebpf-observer.service
	sudo rm -f $(ENV_DIR)/ebpf-observer
	sudo rm -f $(BIN_DIR)/ebpf-observer
	sudo rm -rf $(INSTALL_DIR)
	sudo systemctl daemon-reload
	@echo "Uninstallation complete!"

systemd-start:
	sudo systemctl start ebpf-observer

systemd-stop:
	sudo systemctl stop ebpf-observer

systemd-status:
	sudo systemctl status ebpf-observer

systemd-logs:
	journalctl -u ebpf-observer -f