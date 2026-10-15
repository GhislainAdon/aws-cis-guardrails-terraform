output "config_rule_name" {
  description = "Name of the AWS Config rule watched by the remediation."
  value       = local.rule_name
}

output "config_rule_arn" {
  description = "ARN of the Config rule (null when create_config_rule is false)."
  value       = one(aws_config_config_rule.nacl[*].arn)
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule routing NON_COMPLIANT evaluations."
  value       = aws_cloudwatch_event_rule.non_compliant.arn
}

output "lambda_function_arn" {
  description = "ARN of the remediation Lambda function."
  value       = aws_lambda_function.remediation.arn
}

output "lambda_role_arn" {
  description = "ARN of the IAM role assumed by the remediation Lambda."
  value       = aws_iam_role.remediation.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic receiving remediation reports."
  value       = aws_sns_topic.notifications.arn
}
