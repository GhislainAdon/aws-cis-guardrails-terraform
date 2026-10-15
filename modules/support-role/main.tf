# CIS AWS Foundations Benchmark 1.17:
# "Ensure a support role has been created to manage incidents with AWS Support".
# Security Hub checks that the AWS managed policy AWSSupportAccess is attached
# to at least one IAM role, user or group.

data "aws_partition" "current" {}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "AllowTrustedPrincipals"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []

      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "support" {
  name                 = var.role_name
  path                 = var.role_path
  description          = "CIS 1.17 - manage incidents with AWS Support"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permissions_boundary_arn

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "support_access" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSSupportAccess"
}
