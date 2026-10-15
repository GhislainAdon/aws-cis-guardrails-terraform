data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  # CIS 1.2.0 is published as a global "ruleset"; every other standard is regional.
  standards_arns = {
    for s in var.standards : s => (
      startswith(s, "ruleset/")
      ? "arn:${data.aws_partition.current.partition}:securityhub:::${s}"
      : "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.region}::standards/${s}"
    )
  }
}

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards  = var.enable_default_standards
  control_finding_generator = var.control_finding_generator
  auto_enable_controls      = var.auto_enable_controls
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = local.standards_arns

  standards_arn = each.value

  depends_on = [aws_securityhub_account.this]
}

resource "aws_securityhub_member" "this" {
  for_each = var.members

  account_id = each.key
  email      = each.value
  invite     = var.invite_members

  depends_on = [aws_securityhub_account.this]

  lifecycle {
    precondition {
      condition     = each.key != data.aws_caller_identity.current.account_id
      error_message = "An account cannot be a Security Hub member of itself."
    }
  }
}
