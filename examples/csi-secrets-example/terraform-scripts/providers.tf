#Pinning the provider versions
terraform {
  required_version = ">= 0.14.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

data "aws_eks_cluster" "default" {
  name = "pds-blueprint-control-plane"
}

data "aws_eks_cluster_auth" "default" {
  name = "pds-blueprint-control-plane"
}

# provider for kubernetes 
provider "kubernetes" {
  host                   = data.aws_eks_cluster.default.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.default.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.default.token
}
