output "role_name" {
  description = "Name of the AWS Support role."
  value       = aws_iam_role.support.name
}

output "role_arn" {
  description = "ARN of the AWS Support role."
  value       = aws_iam_role.support.arn
}

output "attached_policy_arn" {
  description = "ARN of the AWS managed policy attached to the role (AWSSupportAccess)."
  value       = aws_iam_role_policy_attachment.support_access.policy_arn
}
