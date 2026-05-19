# ─── VPC ──────────────────────────────────────────────────────────────────────

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # Required: EKS nodes must resolve the API endpoint

  tags = merge(local.common_tags, {
    Name                                        = "${local.name_prefix}-vpc"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  })
}

# ─── Internet Gateway ─────────────────────────────────────────────────────────

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-igw" })
}

# ─── Subnets ──────────────────────────────────────────────────────────────────
# EKS requires subnets in at least 2 AZs.
# Architecture:
#   - 2 public subnets  → NAT GW elastic IPs live here
#   - 2 private subnets → EKS worker nodes live here (no public IP)
#
# Worker nodes in private subnets = better security posture:
#   - Nodes reach the internet via NAT GW (for pulling images, S3, etc.)
#   - Inbound traffic from the internet is blocked by default
#   - Only the metrics SG rule allows specific scraping (if configured)

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index) # .0/24, .1/24
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false # public subnets here only host the NAT GW

  tags = merge(local.common_tags, {
    Name                                        = "${local.name_prefix}-public-${count.index + 1}"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1" # ALB controller autodiscovery
  })
}

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10) # .10/24, .11/24
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name                                        = "${local.name_prefix}-private-${count.index + 1}"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = "1"
  })
}

# ─── NAT Gateway ──────────────────────────────────────────────────────────────
# Single NAT GW in az[0] public subnet.
# Cost: ~$0.045/hr + data transfer.
# Two NAT GWs (HA) would double this cost — not needed for testing.

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-nat-eip" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-nat-gw" })

  depends_on = [aws_internet_gateway.this]
}

# ─── Route Tables ─────────────────────────────────────────────────────────────

# Public route table: 0.0.0.0/0 → IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route table: 0.0.0.0/0 → NAT GW
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ─── Security Groups ──────────────────────────────────────────────────────────

# EKS cluster control-plane security group
# (EKS itself creates the primary SG; this is an additional SG we attach)
resource "aws_security_group" "cluster_additional" {
  name        = "${local.name_prefix}-cluster-additional"
  description = "Additional SG for EKS control plane"
  vpc_id      = aws_vpc.this.id

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-cluster-additional-sg" })
}

# Worker node security group
resource "aws_security_group" "nodes" {
  name        = "${local.name_prefix}-nodes"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.this.id

  # Allow all outbound (for image pulls, S3, OS updates)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Allow inter-node and node→control-plane communication
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Allow node-to-node communication"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nodes-sg"
    # Required for EKS managed node groups to auto-discover this SG
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })
}

# Optional: allow local Prometheus to scrape :8080 on nodes
resource "aws_security_group_rule" "node_metrics_ingress" {
  count = length(var.prometheus_scrape_cidrs) > 0 ? 1 : 0

  type              = "ingress"
  from_port         = var.metrics_port
  to_port           = var.metrics_port
  protocol          = "tcp"
  cidr_blocks       = var.prometheus_scrape_cidrs
  security_group_id = aws_security_group.nodes.id
  description       = "Allow Prometheus scraping of eBPF observer metrics"
}

# Allow control plane to reach nodes (kubelets, webhooks)
resource "aws_security_group_rule" "cluster_to_nodes" {
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster_additional.id
  security_group_id        = aws_security_group.nodes.id
  description              = "Allow control plane to reach kubelet on nodes"
}

resource "aws_security_group_rule" "nodes_to_cluster" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nodes.id
  security_group_id        = aws_security_group.cluster_additional.id
  description              = "Allow nodes to reach EKS API server"
}

# SSM access: nodes in private subnets → SSM agent uses 443 outbound (already allowed)
# No inbound SSH needed — we use Systems Manager Session Manager instead
