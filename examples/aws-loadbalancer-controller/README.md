## Provision and Upload your certificates to AWS ACM. 
1. Provision your TLS Certificates with Venafi - https://confluence.capgroup.com/display/Crypto/Welcome+to+Venafi

2. Download the certificate(s) from Venafi and decrypt the certificate private key before uploading to AWS ACM - 
`openssl rsa -in encrypted.key -out phlp-asp-key.key` 

3. Upload the certificates to ACM in AWS Account & Region where EKS cluster is deployed

## TLS Certificate configuration for Application Load Balancer
https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.1/guide/ingress/cert_discovery/

1. Add annotations to specify arn of certificate and configure listen ports - https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.1/guide/ingress/annotations/#certificate-arn

YAML file reference in examples/aws-loadbalancer-controller/alb-deployment-tls-ingress.yaml 
```
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS":443}]'
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-west-2:836816519470:certificate/c18c808c-f940-4f2b-813a-5d73e8a51f26
``` 


## TLS Certificate for Network Load Balancer
YAML file reference in examples/aws-loadbalancer-controller/nlb-deployment-tls-ingress.yaml 
1. Add the annotations to specify arn of certificate and configure HTTPS port
```
    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: arn:aws:acm:us-west-2:836816519470:certificate/45b5194c-e360-4ba1-bb83-0701bc1a8a80
    service.beta.kubernetes.io/aws-load-balancer-ssl-ports: "https"
``` 
