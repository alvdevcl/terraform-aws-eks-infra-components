podAnnotations: 
  cluster-autoscaler.kubernetes.io/safe-to-evict: ${cluster_autoscaler_safe_to_evict}
  ad.datadoghq.com/aws-cluster-autoscaler.logs: ${cluster_autoscaler_datadog_pod_annotation}

resources:
   limits:
     cpu: 100m
     memory: 750Mi
   requests:
     cpu: 100m
     memory: 500Mi
