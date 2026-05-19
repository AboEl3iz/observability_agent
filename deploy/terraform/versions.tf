terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.3"
    }
  }

  # --------------------------------------------------------------------------
  # LOCAL STATE — fine for one-person testing.
  # Swap to an S3 backend before sharing with a team:
  #
  # backend "s3" {
  #   bucket  = "my-tfstate-bucket"
  #   key     = "ebpf-observer/eks/terraform.tfstate"
  #   region  = "us-east-1"
  #   encrypt = true
  # }
  # --------------------------------------------------------------------------
}
