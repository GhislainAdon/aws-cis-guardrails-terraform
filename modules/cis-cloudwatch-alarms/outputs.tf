output "enabled_controls" {
  description = "CIS control IDs deployed by this module."
  value       = sort(keys(local.controls))
}

output "metric_filter_names" {
  description = "Map of CIS control ID => CloudWatch Logs metric filter name."
  value       = { for id, f in aws_cloudwatch_log_metric_filter.this : id => f.name }
}

output "alarm_names" {
  description = "Map of CIS control ID => CloudWatch alarm name."
  value       = { for id, a in aws_cloudwatch_metric_alarm.this : id => a.alarm_name }
}

output "alarm_arns" {
  description = "Map of CIS control ID => CloudWatch alarm ARN."
  value       = { for id, a in aws_cloudwatch_metric_alarm.this : id => a.arn }
}

output "controls" {
  description = "Resolved data model (title, severity, filter pattern) for each deployed control."
  value = {
    for id, c in local.controls : id => {
      title    = c.title
      severity = c.severity
      pattern  = c.pattern
    }
  }
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives the alarms."
  value       = local.sns_topic_arn
}

output "archiver_function_arn" {
  description = "ARN of the SNS -> S3 archiver Lambda function (null when disabled)."
  value       = one(aws_lambda_function.archiver[*].arn)
}
