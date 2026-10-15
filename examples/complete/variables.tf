variable "region" {
  description = "AWS region of the deployment."
  type        = string
  default     = "eu-west-3"
}

variable "account_id" {
  description = "Target AWS account ID (placeholder)."
  type        = string
  default     = "123456789012"
}

variable "environment" {
  description = "Value of the environment tag."
  type        = string
  default     = "production"
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group of the organization trail."
  type        = string
  default     = "aws-controltower/CloudTrailLogs"
}

variable "alert_emails" {
  description = "Security mailbox(es) subscribed to the alert topics."
  type        = list(string)
  default     = ["security@example.com"]
}

variable "archive_bucket_name" {
  description = "Existing S3 bucket for archived alerts; null disables the archiver."
  type        = string
  default     = null
}

variable "remediation_dry_run" {
  description = "Run the NACL remediation in report-only mode."
  type        = bool
  default     = true
}
