data "aws_eks_cluster" "example" {
  name = "pds-blueprint-control-plane"
}

data "aws_caller_identity" "current" {}

locals {
  oidc_output    = trimprefix(data.aws_eks_cluster.example.identity[0].oidc[0].issuer, "https://")
  aws_account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_policy" "secret_policy" {

  name        = "phlp-secretpolicy"
  description = "IAM Policy for Secrets Manager "

  policy = file("secret_policy.json")

}

resource "aws_iam_role" "secretmanager_role" {
  name                 = "phlp-secretrole"
  permissions_boundary = "arn:aws:iam::836816519470:policy/AdminPermissionsBoundary"

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
            "${local.oidc_output}:sub" : "system:serviceaccount:default:nginx-deployment-sa"
          }
        }
      }
    ]
  })

}

resource "aws_iam_role_policy_attachment" "attach_aws_secret_policy" {
  role       = aws_iam_role.secretmanager_role.name
  policy_arn = aws_iam_policy.secret_policy.arn
}

resource "kubernetes_service_account" "example" {
  metadata {
    name      = "nginx-deployment-sa"
    namespace = "default"

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.secretmanager_role.arn
    }
  }

}
