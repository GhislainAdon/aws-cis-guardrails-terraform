# -----------------------------------------------------------------------------
# Detect (AWS Config) -> route (EventBridge) -> fix (Lambda) -> notify (SNS)
# -----------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  function_name = "${var.name_prefix}-nacl-admin-port-remediation"
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  rule_name     = var.create_config_rule ? aws_config_config_rule.nacl[0].name : var.config_rule_name
}

# 1. Detection - AWS managed rule. Requires an active configuration recorder
#    (provided by Control Tower in every enrolled account).
resource "aws_config_config_rule" "nacl" {
  count = var.create_config_rule ? 1 : 0

  name        = var.config_rule_name
  description = "CIS - network ACLs must not allow ingress from 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389)."

  source {
    owner             = "AWS"
    source_identifier = "NACL_NO_UNRESTRICTED_SSH_RDP"
  }

  scope {
    compliance_resource_types = ["AWS::EC2::NetworkAcl"]
  }

  tags = var.tags
}

# 2. Routing - only NON_COMPLIANT evaluations of this rule reach the Lambda.
resource "aws_cloudwatch_event_rule" "non_compliant" {
  name        = "${var.name_prefix}-nacl-admin-port-non-compliant"
  description = "NON_COMPLIANT evaluations of ${local.rule_name}"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [local.rule_name]
      resourceType   = ["AWS::EC2::NetworkAcl"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.non_compliant.name
  target_id = "nacl-remediation-lambda"
  arn       = aws_lambda_function.remediation.arn

  retry_policy {
    maximum_retry_attempts       = 3
    maximum_event_age_in_seconds = 3600
  }
}

resource "aws_lambda_permission" "from_eventbridge" {
  statement_id  = "AllowInvokeFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.non_compliant.arn
}

# 4. Notification
resource "aws_sns_topic" "notifications" {
  name              = "${var.name_prefix}-nacl-admin-port-remediation"
  kms_master_key_id = var.sns_kms_master_key_id

  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_email_endpoints)

  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = each.value
}
