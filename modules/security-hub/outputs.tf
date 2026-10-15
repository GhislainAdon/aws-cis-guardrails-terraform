output "securityhub_account_id" {
  description = "ID of the Security Hub account resource (null when enable_security_hub is false)."
  value       = one(aws_securityhub_account.this[*].id)
}

output "standards_arns" {
  description = "Map of standard path => standard ARN."
  value       = local.standards_arns
}

output "standards_subscription_ids" {
  description = "Map of standard path => subscription ID."
  value       = { for k, s in aws_securityhub_standards_subscription.this : k => s.id }
}

output "member_ids" {
  description = "Map of member account ID => Security Hub member resource ID."
  value       = { for k, m in aws_securityhub_member.this : k => m.id }
}
