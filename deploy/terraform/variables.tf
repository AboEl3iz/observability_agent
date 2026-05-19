variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster."
  type        = string
  default     = "ebpf-observer-test"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.30"
}

variable "node_instance_type" {
  description = <<-EOT
    EC2 instance type for worker nodes.
    Set to t3.small to comply with AWS Free Tier constraints in this account.
  EOT
  type        = string
  default     = "t3.small"
}

variable "node_desired_count" {
  description = "Desired number of worker nodes."
  type        = number
  default     = 2
}

variable "node_min_count" {
  description = "Minimum number of worker nodes."
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum number of worker nodes."
  type        = number
  default     = 2
}

variable "node_disk_size_gb" {
  description = <<-EOT
    EBS root disk size in GB for each worker node.
    Must be >= 20 GB due to EKS AL2023 AMI snapshot size constraints.
  EOT
  type        = number
  default     = 20
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = <<-EOT
    List of AZs to use. EKS requires at least 2 subnets in different AZs.
    Keeping both nodes in the same AZ avoids cross-AZ data-transfer costs.
  EOT
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "metrics_port" {
  description = "Port the eBPF observer Prometheus metrics endpoint listens on."
  type        = number
  default     = 8080
}

variable "prometheus_scrape_cidrs" {
  description = <<-EOT
    CIDR blocks allowed to scrape :8080 on the worker nodes (Security Group rule).
    Default is 0.0.0.0/0 for easy local testing — tighten to your dev IP in production.
    Set to [] to disable the rule (use kubectl port-forward only).
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default = {
    Project     = "ebpf-observer"
    Environment = "testing"
    ManagedBy   = "terraform"
    Owner       = "devops"
  }
}
