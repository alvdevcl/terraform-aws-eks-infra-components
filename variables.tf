variable "base_domain" {
  type        = string
  default     = "dev.ops360.alveo-sandbox.net"
  description = "Domain name created in Route53 as part of account provisioning"
}

variable "zone_id" {
  type = string
  default = "Z071150923A0COB5971SH"
  description = "Zone Id created in Route53 as part of account provisioning"

}

variable "custom_cert" {
  type        = bool
  default     = false
  description = "Enable flag to use custom certificate for haproxy ingress controller and kubernetes dashboard"
}

#Datadog
variable "datadog_agent_enabled" {
  type        = bool
  default     = false
  description = "Enable flag to deploy Datadog agent to EKS cluster"
}

variable "datadog_apikey" {
  type        = string
  default     = null
  description = "DataDog API Key value"
}

variable "datadog_appkey" {
  type        = string
  default     = null
  description = "DataDog App Key value"
}

variable "datadog_namespace" {
  type        = string
  default     = "datadog"
  description = "DataDog namespace value"
}

variable "datadog_env_tag" {
  type        = string
  default     = "dev"
  description = "datadog environment tag"
}

variable "datadog_agent_image_tag" {
  type        = string
  default     = "7.32.4"
  description = "Datadog Agent Image Tag"
}

variable "datadog_logs_enabled" {
  type        = string
  default     = false
  description = "To enable logging for Datadog"
}

variable "datadog_logs_container_collection_all" {
  type        = string
  default     = false
  description = "To enable logging for for all containers Datadog"
}

variable "haproxy_ingress" {
  type        = bool
  default     = false
  description = "Enable flag to deploy haproxy ingress controller to EKS cluster"
}

#Fluentbit Variables
variable "fluentbit_enable" {
  type        = bool
  default     = false
  description = "Enable flag to deploy fluentbit to EKS cluster"
}

variable "fluentbit_cloudwatch_loggroup_name" {
  type        = string
  default     = "/aws/eks/fluentbit-cloudwatch/logs"
  description = "The name of the CloudWatch Log Group that you want logs sent to"
}

variable "eks_cluster_name" {
  type        = string
  description = "Name of your EKS Control Plane"
}

variable "cluster_autoscaler_enable" {
  type        = bool
  description = "Whether to enable node group to scale the Auto Scaling Group"
  default     = false
}

variable "cluster_autoscaler_num_replica" {
  type        = string
  description = "Number of pod replicas for cluster-autoscaler"
  default     = "2"
}

variable "cluster_autoscaler_datadog_pod_annotation" {
  type        = string
  default     = ""
  description = "Pod Annotation to enable datadog logging via auto-discovery"
}

variable "cluster_autoscaler_safe_to_evict" {
  type        = string
  default     = "true"
  description = "Pod Annotation to determine if autoscaler pods can be evicted. Important to have >2 replicas running for HA"
}

variable "cluster_autoscaler_image_tag" {
  type        = string
  description = "Cluster autoscaler version needs to match your kubernetes version"
}

variable "ingress_svc_name" {
  type        = string
  default     = "haproxy-ingress-kubernetes-ingress"
  description = "The name of kubernetes front end ingress controller service"
}

variable "ingress_namespace" {
  type        = string
  default     = "default"
  description = "The namespace for ingress controller service"
}

#Spot Instances Support
variable "cluster_autoscaler_expander" {
  type        = string
  default     = "random"
  description = "Cluster autoscaler expander option"
}

variable "cluster_autoscaler_expander_priorities" {
  type        = string
  default     = <<EOT
      100:
        - .*
      EOT
  description = "Cluster autoscaler priorities"
}

variable "cluster_autoscaler_balance_similar_node_groups" {
  type        = bool
  default     = false
  description = "Flag to enable the autoscaler to balance nodes across similar node groups in different AZs"
}

# Twistlock chart vars
variable "twistlock_defenders" {
  type        = bool
  default     = true
  description = "Enable flag to deploy Twistlock defenders onto the EKS cluster."
}

variable "haproxy_ingress_controller_tls_secret" {
  type        = string
  default     = null
  description = "k8s secret to use as the ssl-certificate for the ingress controller"
}

# Set the defaults as per ConfigMap: https://www.haproxy.com/documentation/kubernetes/latest/configuration/configmap/
variable "haproxy_ingress_controller_config_timeout_client" {
  type        = string
  default     = "50s"
  description = "The maximum inactivity time on the client side"
}

variable "haproxy_ingress_controller_config_timeout_server" {
  type        = string
  default     = "50s"
  description = "The maximum inactivity time on the server side"
}

#AWS EBS CSI Driver
variable "aws_ebs_csi_driver_enable" {
  type        = bool
  default     = false
  description = "Enable flag to attach EBS CSI driver to EKS cluster"
}

variable "aws_ebs_csi_driver_service_account" {
  type        = string
  default     = "ebs-csi-controller-sa"
  description = "Service Account for EBS CSI driver deployment"
}

#AWS Load Balancer Controller
variable "permissions_boundary" {
  type        = string
  default     = null
  description = "aws arn of permissions boundary to attach to Load Balancer Controller Role"
}

variable "tags" {
  description = "AWS tags which should be applied to all resources that Terraform creates"
  type        = map(string)
  default     = null
}

##Secrets Store CSI Provider Variables - https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html
variable "secrets_store_csi_enable" {
  type        = string
  default     = false
  description = "Deploy Secrets Store CSI Driver"
}

variable "secrets_store_csi_enableSecretRotation" {
  type        = string
  default     = false
  description = "Auto rotation of mounted contents and synced kubernetes secrets from AWS Secrets Manager"
}

#https://secrets-store-csi-driver.sigs.k8s.io/topics/secret-auto-rotation.html
variable "secrets_store_csi_rotationPollInterval" {
  type        = string
  default     = "2m"
  description = "Interval on how frequently mounted contents for pods & secrets needs to be re-synced with secrets manager"
}

variable "secrets_store_csi_enable_syncSecret" {
  type        = bool
  default     = false
  description = "Enable Syncing. This is required for using Environment Variables. Warning: this will allow the driver to access k8s secrets"
}
variable "secrets_store_csi_enable_providerHealthCheck" {
  type        = bool
  default     = false
  description = "Enable HealthCheck for secrets CSI driver. This will show a log message if there is an issue with connecting to AWS"
}

variable "csi_secrets_store_provider_aws_image" {
  type        = string
  default     = "cgregistry.capgroup.com/aws-secrets-manager/secrets-store-csi-driver-provider-aws:1.0.r2-2021.08.13.20.34-linux-amd64"
  description = "Image for secrets-store-csi-driver-provider-aws daemonset"
}

##EFS CSI Driver Variables 
variable "efs_csi_driver_enable" {
  type        = string
  default     = false
  description = "Deploy EFS CSI Driver"
}

#GPU Nvidia Device Plugin
variable "nvidia_device_plugin_enable" {
  type        = string
  default     = false
  description = "Deploy nvidia device plugin for gpu workloads"
}

#EBS-CSI-DRIVER EKS Add-On
variable "aws_ebs_csi_driver_resolve_conflicts" {
  type        = string
  default     = "NONE"
  description = "NONE or OVERWRITE which will allow the add-on to overwrite your custom settings"
}

variable "aws_ebs_csi_driver_addon_version" {
  type        = string
  default     = "v1.10.0-eksbuild.1" #Default version is for EKS V1.22, make sure you update this to match your k8s version
  description = "EBS-CSI-DRIVER version, please ensure the version is compatible with your k8s version"
}

variable "cluster_autoscaler_cordon_node_before_terminating" {
  type        = bool
  default     = true
  description = "cordon node before terminating cluster autoscaler parameter"
}
