output "cis_alarm_names" {
  description = "CIS control ID => CloudWatch alarm name."
  value       = module.cis_alarms.alarm_names
}

output "cis_alert_topic_arn" {
  description = "SNS topic receiving the CIS alarms."
  value       = module.cis_alarms.sns_topic_arn
}

output "nacl_remediation_lambda_arn" {
  description = "ARN of the NACL remediation Lambda."
  value       = module.nacl_remediation.lambda_function_arn
}

output "security_hub_standards" {
  description = "Subscribed Security Hub standards."
  value       = module.security_hub.standards_arns
}

output "support_role_arn" {
  description = "ARN of the CIS 1.17 support role."
  value       = module.support_role.role_arn
}
