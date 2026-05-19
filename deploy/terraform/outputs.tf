output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "EKS API server endpoint URL."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_version" {
  description = "Kubernetes version running on the cluster."
  value       = aws_eks_cluster.this.version
}

output "cluster_oidc_issuer" {
  description = "OIDC issuer URL (for IRSA configuration)."
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "node_group_arn" {
  description = "ARN of the EKS managed node group."
  value       = aws_eks_node_group.workers.arn
}

output "node_role_arn" {
  description = "IAM role ARN used by worker nodes."
  value       = aws_iam_role.eks_node.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 artifact bucket."
  value       = aws_s3_bucket.artifacts.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 artifact bucket."
  value       = aws_s3_bucket.artifacts.arn
}

output "vpc_id" {
  description = "ID of the VPC created for the cluster."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (where nodes run)."
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets."
  value       = aws_subnet.public[*].id
}

# ── Convenience commands ──────────────────────────────────────────────────────

output "kubeconfig_command" {
  description = "Run this command to configure kubectl to talk to the cluster."
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.this.name}"
}

output "eks_push_command" {
  description = "Run this command to upload artifacts to S3 after building."
  value       = "make eks-push S3_BUCKET=${aws_s3_bucket.artifacts.id} AWS_REGION=${var.aws_region}"
}

output "monitoring_instructions" {
  description = "Instructions to start local Prometheus/Grafana scraping the EKS nodes."
  value       = <<-EOT
    # 1. Start port-forwarding (run in separate terminal):
    make eks-port-forward

    # 2. Start local monitoring stack:
    make monitoring-up

    # 3. Open dashboards:
    #    Prometheus → http://localhost:9090
    #    Grafana    → http://localhost:3000  (admin/admin)
  EOT
}

output "cost_reminder" {
  description = "Cost reminder — always destroy when done testing!"
  value       = <<-EOT
    ⚠️  COST REMINDER:
       EKS control plane: ~$0.10/hr ($2.40/day)
       2x t3.small nodes: ~$0.00/hr (Free Tier eligible!)
       NAT Gateway: ~$0.045/hr ($1.08/day)
       Total estimate: ~$3.48/day

    💡 To stop all charges run:
       cd deploy/terraform && terraform destroy
  EOT
}
