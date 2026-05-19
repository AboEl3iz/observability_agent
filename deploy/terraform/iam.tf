# ─── EKS Cluster Role ─────────────────────────────────────────────────────────

data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    sid     = "EKSClusterAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${local.name_prefix}-eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json
  description        = "IAM role assumed by the EKS control plane"

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
}

# ─── EKS Node Role ────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "eks_node_assume_role" {
  statement {
    sid     = "EKSNodeAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_node" {
  name               = "${local.name_prefix}-eks-node-role"
  assume_role_policy = data.aws_iam_policy_document.eks_node_assume_role.json
  description        = "IAM role assumed by EKS worker nodes"

  tags = local.common_tags
}

# AWS-managed policies required for EKS managed node groups
resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_ecr_readonly" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# SSM — allows Session Manager shell access to nodes without SSH bastion
resource "aws_iam_role_policy_attachment" "eks_ssm" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ─── Custom S3 Artifact Policy ────────────────────────────────────────────────
# Nodes need read access to pull the observer binary + eBPF objects at boot.
# Scoped to the specific artifact bucket only — least-privilege.

data "aws_iam_policy_document" "s3_artifact_read" {
  statement {
    sid    = "ListArtifactBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid    = "GetArtifacts"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }
}

resource "aws_iam_policy" "s3_artifact_read" {
  name        = "${local.name_prefix}-s3-artifact-read"
  description = "Allow EKS nodes to read eBPF observer artifacts from S3"
  policy      = data.aws_iam_policy_document.s3_artifact_read.json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_node_s3_artifacts" {
  role       = aws_iam_role.eks_node.name
  policy_arn = aws_iam_policy.s3_artifact_read.arn
}

# ─── Instance Profile ─────────────────────────────────────────────────────────
# The instance profile wraps the node role — EC2 uses it to get credentials via IMDS.

resource "aws_iam_instance_profile" "eks_node" {
  name = "${local.name_prefix}-eks-node-profile"
  role = aws_iam_role.eks_node.name

  tags = local.common_tags
}

# ─── OIDC Provider (for future IRSA use) ─────────────────────────────────────
# Not strictly required now but zero-cost and enables fine-grained IAM
# for pods via IAM Roles for Service Accounts.

data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-oidc" })
}
