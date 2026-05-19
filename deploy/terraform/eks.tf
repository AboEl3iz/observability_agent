# ─── EKS Cluster ──────────────────────────────────────────────────────────────

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = concat(
      aws_subnet.private[*].id,
      aws_subnet.public[*].id
    )
    security_group_ids      = [aws_security_group.cluster_additional.id]
    endpoint_private_access = true          # Nodes in private subnets reach API privately
    endpoint_public_access  = true          # You reach kubectl from your dev machine
    public_access_cidrs     = ["0.0.0.0/0"] # Tighten to your dev IP for security
  }

  # Enable EKS control-plane logging to CloudWatch
  # Audit and authenticator logs are important for security investigations
  enabled_cluster_log_types = ["audit", "authenticator", "controllerManager"]

  # Kubernetes network config
  kubernetes_network_config {
    service_ipv4_cidr = "172.20.0.0/16"
    ip_family         = "ipv4"
  }

  # EKS Add-ons — managed by AWS, always up to date
  # (configured separately below to allow version pinning)

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_cloudwatch_log_group.eks_cluster,
  ]

  tags = merge(local.common_tags, { Name = var.cluster_name })
}

# CloudWatch log group for EKS control-plane logs
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 7 # Low retention — just for testing; avoids log storage costs

  tags = local.common_tags
}

# ─── EKS Add-ons ──────────────────────────────────────────────────────────────

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = local.common_tags
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "kube-proxy"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = local.common_tags
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  # CoreDNS requires at least one worker node to schedule on
  depends_on = [aws_eks_node_group.workers]

  tags = local.common_tags
}

# EKS Pod Identity addon — enables IRSA v2 (more secure than legacy IRSA)
resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_node_group.workers]

  tags = local.common_tags
}

# ─── User-Data (cloud-init) ───────────────────────────────────────────────────
# Renders the install.sh template with Terraform-provided values.
# The rendered script is base64-encoded and passed to the launch template.

data "cloudinit_config" "node_bootstrap" {
  gzip          = false
  base64_encode = true

  # Part 1: the EKS-specific bootstrap (AL2023 handles kubelet registration)
  # Part 2: our custom eBPF observer install
  part {
    content_type = "text/x-shellscript"
    filename     = "99-ebpf-observer-install.sh"
    content = templatefile("${path.module}/userdata/install.sh", {
      s3_bucket    = aws_s3_bucket.artifacts.id
      s3_prefix    = local.s3_releases_prefix
      aws_region   = var.aws_region
      metrics_port = var.metrics_port
    })
  }
}

# ─── Launch Template ──────────────────────────────────────────────────────────
# Custom launch template lets us:
#   - Inject the user-data bootstrap script
#   - Set a specific root volume size (30 GB — enough for kubelet + eBPF .o files)
#   - Attach the node security group
#   - Configure IMDSv2 (required — IMDSv1 disabled for security)

resource "aws_launch_template" "eks_nodes" {
  name_prefix            = "${local.name_prefix}-node-"
  instance_type          = var.node_instance_type
  update_default_version = true

  user_data = data.cloudinit_config.node_bootstrap.rendered

  # Root EBS volume
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.node_disk_size_gb
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  # Force IMDSv2 — prevents SSRF-based metadata exfiltration attacks
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 2          # Must be 2 for pods using IMDSv2
    instance_metadata_tags      = "enabled"
  }

  # Attach our custom node security group
  vpc_security_group_ids = [aws_security_group.nodes.id]

  # Enable detailed monitoring (1-minute CloudWatch metrics)
  # Free for EC2 basic monitoring; detailed is $0.0035/metric/month — acceptable for testing
  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-worker"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-worker-root"
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# ─── Managed Node Group ───────────────────────────────────────────────────────

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name_prefix}-workers"
  node_role_arn   = aws_iam_role.eks_node.arn

  # Deploy into private subnets — nodes have no public IPs
  subnet_ids = aws_subnet.private[*].id

  # Use our custom launch template
  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = aws_launch_template.eks_nodes.latest_version
  }

  scaling_config {
    desired_size = var.node_desired_count
    min_size     = var.node_min_count
    max_size     = var.node_max_count
  }

  # AL2023 AMI type — kernel 6.1, cgroup v2, BTF enabled (required for eBPF CO-RE)
  ami_type = "AL2023_x86_64_STANDARD"

  # ON_DEMAND for reliability — SPOT can be interrupted mid-test
  capacity_type = "ON_DEMAND"

  # Let the node update strategy drain gracefully
  update_config {
    max_unavailable = 1
  }

  # Taint: allow scheduling on these nodes without restrictions
  # (no special taints needed for a test cluster)

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_ecr_readonly,
    aws_iam_role_policy_attachment.eks_ssm,
    aws_iam_role_policy_attachment.eks_node_s3_artifacts,
    # S3 VPC endpoint must exist before nodes boot and try to pull from S3
    aws_vpc_endpoint.s3,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-workers"
  })
}

# ─── CloudWatch Billing Alarm ─────────────────────────────────────────────────
# Safety net: alert when estimated charges exceed $10 USD.
# Requires a billing alarm SNS topic to exist in us-east-1.
# NOTE: CloudWatch billing metrics are only in us-east-1 — this resource
#       must be created there regardless of cluster region.

resource "aws_cloudwatch_metric_alarm" "billing_alert" {
  # Only create this if deploying in us-east-1 — billing metrics live there.
  # For other regions, set up the alarm manually or use AWS Budgets (below).
  count = var.aws_region == "us-east-1" ? 1 : 0

  provider            = aws
  alarm_name          = "${local.name_prefix}-billing-alert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = 86400 # check once per day
  statistic           = "Maximum"
  threshold           = 10 # USD
  alarm_description   = "Alert when estimated AWS charges exceed $10 USD — destroy testing infra!"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Currency = "USD"
  }

  tags = local.common_tags
}

# AWS Budgets: works across all regions and is more reliable than CloudWatch billing alarms
resource "aws_budgets_budget" "testing" {
  name         = "${local.name_prefix}-test-budget"
  budget_type  = "COST"
  limit_amount = "15"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80 # alert at 80% of $15 = $12
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["root"] # Replace with your email in terraform.tfvars
  }
}
