# Complete example: the four CIS guardrails deployed in a single account.
# In a Control Tower landing zone the CloudWatch alarms live in the account
# that owns the organization trail log group (management account), while the
# other modules are typically rolled out to every account by an account
# customization pipeline.

locals {
  # The landing zone tag policy rejects any other key.
  tags = {
    environment = var.environment
    owner       = "platform-team"
    createdby   = "terraform"
    account     = var.account_id
  }
}

module "cis_alarms" {
  source = "../../modules/cis-cloudwatch-alarms"

  name_prefix               = "lz"
  cloudtrail_log_group_name = var.cloudtrail_log_group_name
  metric_namespace          = "CISBenchmark"
  enabled_controls          = null # all 15 CIS 4.x controls
  alert_email_endpoints     = var.alert_emails

  enable_sns_archiver = var.archive_bucket_name != null
  archive_bucket_name = var.archive_bucket_name

  tags = local.tags
}

module "nacl_remediation" {
  source = "../../modules/nacl-admin-port-remediation"

  name_prefix           = "lz"
  admin_ports           = [22, 3389]
  dry_run               = var.remediation_dry_run
  alert_email_endpoints = var.alert_emails

  tags = local.tags
}

module "security_hub" {
  source = "../../modules/security-hub"

  standards = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/3.0.0",
  ]

  # When this account is the Security Hub administrator:
  # members = { "<12-digit-account-id>" = "security@example.com" }
  members = {}
}

module "support_role" {
  source = "../../modules/support-role"

  role_name              = "aws-support-incident-role"
  trusted_principal_arns = ["arn:aws:iam::${var.account_id}:role/platform-security-engineers"]

  tags = local.tags
}
