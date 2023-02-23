#Pinning the provider versions
terraform {
  required_version = ">= 0.12.28"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.3.2"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.27"
    }
  }
}
