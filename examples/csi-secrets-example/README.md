# CSI Secrets Example

## Terraform 
- Module will create IAM Role with attached IAM Policy that has permissions to retrieve secrets manager
- IAM Role will have trust relationship with EKS OIDC Provider

## Kubernetes YAML 
- Service Account that has annotation of IAM Role created
- SecretProviderClass to provide driver configurations and provider parameters to CSI Driver
- Nginx Deployment that mounts the SecretProviderClass


## Kubectl commands
kubectl get secretproviderclass 

kubectl get secretproviderclasspodstatus