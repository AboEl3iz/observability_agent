provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

# Random suffix keeps S3 bucket names globally unique
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  # Short, stable identifier reused across all resource names
  name_prefix = "${var.cluster_name}-${random_id.suffix.hex}"

  # Convenience: the S3 key prefix used by install.sh
  s3_releases_prefix = "releases/latest"

  # Common tags merged with per-resource tags
  common_tags = merge(var.tags, {
    ClusterName = var.cluster_name
  })
}

# ── Current account / partition data ──────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
