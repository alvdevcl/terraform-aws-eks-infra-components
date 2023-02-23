output "ingress_elb" {
  value       = var.haproxy_ingress ? element(split("-", data.kubernetes_service.ingress[0].status.0.load_balancer.0.ingress.0.hostname), 1) : ""
  description = "Ingress load balancer."
  depends_on = [
    helm_release.haproxy-ingress-controller
  ]
}
