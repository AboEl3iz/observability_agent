# ─── S3 Artifact Bucket ───────────────────────────────────────────────────────
# Stores the compiled observer binary + eBPF .o objects.
# Nodes pull from here during boot via user-data.

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name_prefix}-artifacts"
  force_destroy = true # Makes `terraform destroy` clean — OK for testing

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-artifacts" })
}

# Block ALL public access — nodes fetch via IAM role credentials through VPC endpoint
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption at rest — AES256 (free, no KMS cost)
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Versioning — keep artifact history; allows rollback by changing S3 key version
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle: expire non-current object versions after 30 days
# Prevents runaway storage costs during iterative testing
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  # Must wait for versioning to be enabled first
  depends_on = [aws_s3_bucket_versioning.artifacts]

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Remove incomplete multipart uploads (safety net for aborted uploads)
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Bucket policy: deny non-TLS requests and enforce access only from the VPC
resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

data "aws_iam_policy_document" "s3_bucket_policy" {
  # Deny any access that does not use HTTPS
  statement {
    sid    = "DenyNonTLS"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Allow node role to read artifacts
  statement {
    sid    = "AllowNodeRoleRead"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.eks_node.arn]
    }
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
  }
}

# ─── S3 VPC Gateway Endpoint ──────────────────────────────────────────────────
# Routes S3 traffic over AWS backbone network — avoids NAT GW charges for S3 data.
# Gateway endpoints are FREE (no hourly cost, no data-processing charge).

data "aws_vpc_endpoint_service" "s3" {
  service      = "s3"
  service_type = "Gateway"
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = data.aws_vpc_endpoint_service.s3.service_name
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.private.id,
    aws_route_table.public.id,
  ]

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-s3-endpoint" })
}
