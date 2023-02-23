resource "helm_release" "haproxy-ingress-controller" {
  count = var.haproxy_ingress ? 1 : 0

  name       = "haproxy-ingress"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "kubernetes-ingress"
  version    = "1.12.1"
  timeout    = 600

  set {
    name = "controller.kind"
    #value = "DaemonSet"
    value = "Deployment"
  }

  #Number of ingress replicas. Default is 2
  set {
    name  = "controller.service.type"
    value = "LoadBalancer"
  }

  set {
    name  = "defaultBackend.replicaCount"
    value = "2"
  }

  set {
    type  = "string"
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal"
    value = "10.0.0.0/8"
  }

  set {
    type  = "string"
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-cross-zone-load-balancing-enabled"
    value = "true"
  }

  #set image registry
  set {
    name  = "controller.image.repository"
    value = "cgregistry.capgroup.com/haproxytech/kubernetes-ingress"
  }

  #set defaultbackend deployment image registry
  set {
    name  = "defaultBackend.image.repository"
    value = "cgregistry.capgroup.com/defaultbackend-amd64"
  }

  #Set Node Selectors to target ON_DEMAND instances only
  set {
    name  = "defaultBackend.nodeSelector.eks\\.amazonaws\\.com/capacityType"
    value = "ON_DEMAND"
  }

  set {
    name  = "controller.nodeSelector.eks\\.amazonaws\\.com/capacityType"
    value = "ON_DEMAND"
  }

  # Set the controller configmap data: https://www.haproxy.com/documentation/kubernetes/latest/configuration/configmap/
  set {
    name  = "controller.config.timeout-client"
    value = var.haproxy_ingress_controller_config_timeout_client
  }

  set {
    name  = "controller.config.timeout-server"
    value = var.haproxy_ingress_controller_config_timeout_server
  }

  dynamic "set" {
    for_each = var.haproxy_ingress_controller_tls_secret == null ? [] : [var.haproxy_ingress_controller_tls_secret]
    content {
      name  = "controller.defaultTLSSecret.secret"
      value = var.haproxy_ingress_controller_tls_secret
    }
  }
}


# Deploy DataDog agent
resource "helm_release" "datadog" {
  count = var.datadog_agent_enabled ? 1 : 0

  name             = "datadog"
  repository       = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart            = "datadog"
  version          = "2.28.3"
  namespace        = var.datadog_namespace
  create_namespace = true
  timeout          = 600

  set_sensitive {
    name  = "datadog.apiKey"
    value = var.datadog_apikey
  }

  set_sensitive {
    name  = "datadog.appKey"
    value = var.datadog_appkey
  }

  #Logging
  set {
    name  = "datadog.logs.enabled"
    value = var.datadog_logs_enabled
  }

  set {
    name  = "datadog.logs.containerCollectAll"
    value = var.datadog_logs_container_collection_all
  }

  #Tagging
  set {
    name  = "datadog.tags"
    value = var.datadog_env_tag
  }

  set {
    name  = "datadog.kubelet.tlsVerify"
    value = "false"
  }

  set {
    name  = "datadog.processAgent.processCollection"
    value = "true"
  }

  #Set registry to pull datadog images from
  set {
    name  = "registry"
    value = "cgregistry.capgroup.com/datadog"
  }

  #Agent Version
  set {
    name  = "agents.image.tag"
    value = var.datadog_agent_image_tag
  }

  #Set dependency chart kube-state-metrics image repo
  set {
    name  = "kube-state-metrics.image.repository"
    value = "cgregistry.capgroup.com/coreos/kube-state-metrics"
  }

  #For CRI runtime
  #Enable below section once EKS use containerd runtime - https://aws.amazon.com/blogs/containers/amazon-eks-1-21-released/
  #set {
  #  name  = "datadog.criSocketPath"
  #  value = "/var/run/containerd/containerd.sock"
  #}

}

resource "helm_release" "fluentbit" {
  count = var.fluentbit_enable ? 1 : 0

  name             = "fluentbit"
  repository       = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart            = "aws-for-fluent-bit"
  version          = "0.1.19"
  namespace        = "amazon-cloudwatch"
  create_namespace = true
  timeout          = 600

  set {
    name  = "image.repository"
    value = "cgregistry.capgroup.com/amazon/aws-for-fluent-bit"
  }

  set {
    name  = "image.tag"
    value = "2.26.0"
  }

  set {
    name  = "cloudWatch.region"
    value = data.aws_region.current.name
  }

  #Name of cloudwatch log groups to send logs to
  set {
    name  = "cloudWatch.logGroupName"
    value = var.fluentbit_cloudwatch_loggroup_name
  }

  set {
    name  = "firehose.enabled"
    value = false
  }

  set {
    name  = "kinesis.enabled"
    value = false
  }

  set {
    name  = "elasticsearch.enabled"
    value = false
  }

}

#AWS EBS CSI Driver Role
resource "aws_iam_role" "aws_ebs_csi_driver_role" {
  count                = var.aws_ebs_csi_driver_enable ? 1 : 0
  name                 = "${var.eks_cluster_name}-AmazonEKS_EBS_CSI_DriverRole"
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${local.aws_account_id}:oidc-provider/${local.oidc_output}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${local.oidc_output}:sub" : "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { "compliance-app" = "cross-account" })
}

#EBS policy attach 
resource "aws_iam_role_policy_attachment" "attach_aws_ebs_csi_driver_policy" {
  count      = var.aws_ebs_csi_driver_enable ? 1 : 0
  role       = aws_iam_role.aws_ebs_csi_driver_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"

}

#EBS-CSI-DRIVER add-on install
resource "aws_eks_addon" "aws_ebs_csi_driver" {

  count = var.aws_ebs_csi_driver_enable ? 1 : 0

  cluster_name             = var.eks_cluster_name
  addon_name               = "aws-ebs-csi-driver"
  resolve_conflicts        = var.aws_ebs_csi_driver_resolve_conflicts
  addon_version            = var.aws_ebs_csi_driver_addon_version
  service_account_role_arn = aws_iam_role.aws_ebs_csi_driver_role[0].arn

}

# Deploy Twistlock defenders
resource "helm_release" "twistlock_defenders" {
  count = var.twistlock_defenders ? 1 : 0

  name             = "twistlock-defender"
  repository       = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart            = "twistlock-defender"
  version          = "22.06.197"
  namespace        = "twistlock"
  create_namespace = true
  timeout          = 600

  #For containerd runtime.  EKS V1.24 will configure containerd as default, as of 08/09 EKS V1.22 is the latest
  # set {
  #   name  = "defender_type"
  #   value = "cri"
  # }

  # set {
  #   name  = "containers_storage_mount"
  #   value = "/var/lib/containers"
  # }

  # set {
  #   name  = "selinux_header"
  #   value = "seLinuxOptions:"
  # }

  # set {
  #   name  = "selinux_options"
  #   value = "type: spc_t"
  # }

}

#Kubernetes Cluster AutoScaler - https://github.com/kubernetes/autoscaler
resource "helm_release" "cluster_autoscaler" {
  count      = var.cluster_autoscaler_enable ? 1 : 0
  name       = "cluster-autoscaler"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "cluster-autoscaler"
  version    = "9.19.2"
  timeout    = 600

  namespace = "kube-system"

  values = [templatefile("${path.module}/templates/cluster-autoscaler-helm-values.yaml.tpl", {
    cluster_autoscaler_datadog_pod_annotation = jsonencode(var.cluster_autoscaler_datadog_pod_annotation),
    cluster_autoscaler_safe_to_evict          = jsonencode(var.cluster_autoscaler_safe_to_evict)
  })]

  set {
    name  = "autoDiscovery.clusterName"
    value = var.eks_cluster_name
  }

  set {
    name  = "awsRegion"
    value = data.aws_region.current.name
  }

  set {
    name  = "image.repository"
    value = "cgregistry.capgroup.com/autoscaling/cluster-autoscaler"
  }

  #Image Tag must match your kubernetes version
  set {
    name  = "image.tag"
    value = var.cluster_autoscaler_image_tag
  }

  #Spot Instance Support
  set {
    name  = "nodeSelector.eks\\.amazonaws\\.com/capacityType"
    value = "ON_DEMAND"
  }

  #Default value for cluster autoscaler expander
  set {
    name  = "extraArgs.expander"
    value = var.cluster_autoscaler_expander
  }

  set {
    name  = "expanderPriorities"
    value = var.cluster_autoscaler_expander_priorities
  }

  set {
    name  = "extraArgs.balance-similar-node-groups"
    value = var.cluster_autoscaler_balance_similar_node_groups
  }

  set {
    name  = "extraArgs.cordon-node-before-terminating"
    value = var.cluster_autoscaler_cordon_node_before_terminating
  }

  set {
    name  = "rbac.serviceAccount.name"
    value = "cluster-autoscaler"
  }

  set {
    name  = "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.cluster_autoscaler_role[0].arn
  }

  set {
    name  = "replicaCount"
    value = var.cluster_autoscaler_num_replica
  }

}

resource "aws_iam_policy" "cluster_autoscaler_policy" {

  count = var.cluster_autoscaler_enable ? 1 : 0

  name        = "${var.eks_cluster_name}-autoscaler-Policy"
  description = "IAM Policy for EKS Cluster AutoScaler"

  policy = file("${path.module}/files/cluster_autoscaler_policy.json")

  tags = var.tags

}

resource "aws_iam_role" "cluster_autoscaler_role" {

  count = var.cluster_autoscaler_enable ? 1 : 0

  name                 = "${var.eks_cluster_name}-cluster-autoscaler-role"
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${local.aws_account_id}:oidc-provider/${local.oidc_output}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${local.oidc_output}:sub" : "system:serviceaccount:kube-system:cluster-autoscaler"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { "compliance-app" = "cross-account" })

}

resource "aws_iam_role_policy_attachment" "attach_cluster_autoscaler_policy" {

  count = var.cluster_autoscaler_enable ? 1 : 0

  role       = aws_iam_role.cluster_autoscaler_role[0].name
  policy_arn = aws_iam_policy.cluster_autoscaler_policy[0].arn
}

#Secrets Manager
resource "helm_release" "secrets_store_csi_driver" {

  count = var.secrets_store_csi_enable ? 1 : 0

  name       = "csi-secrets-store"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "secrets-store-csi-driver"
  version    = "1.0.1"
  namespace  = "kube-system"
  timeout    = 600

  #Update image pull to cgregistry
  set {
    name  = "linux.image.repository"
    value = "cgregistry.capgroup.com/csi-secrets-store/driver"
  }

  set {
    name  = "linux.registrarImage.repository"
    value = "cgregistry.capgroup.com/sig-storage/csi-node-driver-registrar"
  }

  set {
    name  = "linux.livenessProbeImage.repository"
    value = "cgregistry.capgroup.com/sig-storage/livenessprobe"
  }

  set {
    name  = "linux.crds.image.repository"
    value = "cgregistry.capgroup.com/csi-secrets-store/driver-crds"
  }

  set {
    name  = "enableSecretRotation"
    value = var.secrets_store_csi_enableSecretRotation
  }

  set {
    name  = "rotationPollInterval"
    value = var.secrets_store_csi_rotationPollInterval
  }

  set {
    name  = "syncSecret.enabled"
    value = var.secrets_store_csi_enable_syncSecret
  }

  set {
    name  = "providerHealthCheck"
    value = var.secrets_store_csi_enable_providerHealthCheck
  }
}

resource "helm_release" "csi_secrets_store_provider_aws" {

  count = var.secrets_store_csi_enable ? 1 : 0

  name       = "csi-secrets-store-provider-aws"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "csi-secrets-store-provider-aws"
  version    = "0.1.0"
  namespace  = "kube-system"
  timeout    = 600

  set {
    name  = "image"
    value = var.csi_secrets_store_provider_aws_image
  }

}

#AWS EFS CSI Driver Deployment
resource "aws_iam_policy" "efs_csi_driver_policy" {

  count = var.efs_csi_driver_enable ? 1 : 0

  name        = "${var.eks_cluster_name}-efs-csi-driver"
  description = "IAM Policy for EFS CSI Driver"

  policy = file("${path.module}/files/aws_efs_csi_driver_policy.json")

  tags = var.tags

}

resource "aws_iam_role" "aws_efs_csi_driver_role" {

  count = var.efs_csi_driver_enable ? 1 : 0

  name                 = "${var.eks_cluster_name}-efs-csi-driver-role"
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${local.aws_account_id}:oidc-provider/${local.oidc_output}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${local.oidc_output}:sub" : "system:serviceaccount:kube-system:efs-csi-controller-sa"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { "compliance-app" = "cross-account" })

}

resource "aws_iam_role_policy_attachment" "attach_aws_efs_csi_policy" {

  count = var.efs_csi_driver_enable ? 1 : 0

  role       = aws_iam_role.aws_efs_csi_driver_role[0].name
  policy_arn = aws_iam_policy.efs_csi_driver_policy[0].arn
}

resource "helm_release" "aws_efs_csi_provider" {

  count = var.efs_csi_driver_enable ? 1 : 0

  name       = "aws-efs-csi-driver"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "aws-efs-csi-driver"
  version    = "2.2.7"
  namespace  = "kube-system"
  timeout    = 600

  set {
    name  = "image.repository"
    value = "cgregistry.capgroup.com/amazon/aws-efs-csi-driver"
  }

  set {
    name  = "controller.serviceAccount.create"
    value = "true"
  }

  set {
    name  = "controller.serviceAccount.name"
    value = "efs-csi-controller-sa"
  }

  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.aws_efs_csi_driver_role[0].arn
  }
  set {
    name  = "node.resources.limits.cpu"
    value = "1000m"
  }
  set {
    name  = "node.resources.limits.memory"
    value = "1024Mi"
  }
  set {
    name  = "node.resources.requests.cpu"
    value = "100m"
  }
  set {
    name  = "node.resources.requests.memory"
    value = "128Mi"
  }

}

resource "helm_release" "nvidia_device_plugin" {

  count = var.nvidia_device_plugin_enable ? 1 : 0

  name       = "nvidia-device-plugin"
  repository = "https://cgrepo.capgroup.com/repository/cghelm/"
  chart      = "nvidia-device-plugin"
  version    = "0.11.0"
  namespace  = "kube-system"
  timeout    = 600

  values = [
    file("${path.module}/templates/nvidia-device-plugin-helm-values.yaml")
  ]

}

# Terraform aws_route53_record resource ignores dualstack prefix in Route 53 alias names
#
# https://github.com/terraform-providers/terraform-provider-aws/pull/10672 
#

############################################
##  Data
############################################
data "aws_route53_zone" "main" {
  # name         = var.base_domain
  zone_id       = var.zone_id
  private_zone = true
}

data "aws_elb_hosted_zone_id" "main" {}

data "kubernetes_service" "ingress" {

  count = var.haproxy_ingress ? 1 : 0
  #count = 1
  metadata {
    name      = var.ingress_svc_name
    namespace = var.ingress_namespace
  }
  depends_on = [
    helm_release.haproxy-ingress-controller
  ]
}

# # Load Balancer name cannot be specified from Kubernetes and AWS API does not allow
# # filtering Load Balancer resources by tags
# # https://github.com/kubernetes/kubernetes/issues/29789
# # 
# # kubectl get svc/my-ingress-kubernetes-ingress -ojson | jq -r '.status.loadBalancer.ingress[0].hostname' | awk -F "-" '{ print $1}'
# #

data "aws_elb" "ingress" {
  count = var.haproxy_ingress ? 1 : 0
  #count = 1
  name = element(split("-", data.kubernetes_service.ingress[0].status.0.load_balancer.0.ingress.0.hostname), 1)
}


data "aws_eks_cluster" "control_plane" {
  name = var.eks_cluster_name
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  oidc_output    = trimprefix(data.aws_eks_cluster.control_plane.identity[0].oidc[0].issuer, "https://")
  aws_account_id = data.aws_caller_identity.current.account_id
}
