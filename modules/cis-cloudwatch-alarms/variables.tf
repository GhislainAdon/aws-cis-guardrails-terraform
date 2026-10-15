variable "cloudtrail_log_group_name" {
  description = "Name of the existing CloudWatch Logs group that receives the organization CloudTrail (for example the Control Tower trail log group)."
  type        = string

  validation {
    condition     = length(var.cloudtrail_log_group_name) > 0
    error_message = "cloudtrail_log_group_name must not be empty."
  }
}

variable "name_prefix" {
  description = "Prefix used for metric filter and alarm names."
  type        = string
  default     = "lz"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-32 characters: letters, digits, '-' or '_'."
  }
}

variable "metric_namespace" {
  description = "CloudWatch metric namespace for the CIS metrics."
  type        = string
  default     = "CISBenchmark"
}

variable "enabled_controls" {
  description = "CIS 4.x control IDs to deploy (for example [\"4.1\", \"4.3\"]). null deploys all 15 controls."
  type        = list(string)
  default     = null

  validation {
    condition = var.enabled_controls == null ? true : alltrue([
      for id in var.enabled_controls : can(regex("^4\\.([1-9]|1[0-5])$", id))
    ])
    error_message = "enabled_controls only accepts CIS control IDs between 4.1 and 4.15."
  }
}

variable "alarm_period" {
  description = "Period, in seconds, over which the metric is evaluated."
  type        = number
  default     = 300
}

variable "alarm_evaluation_periods" {
  description = "Number of periods over which data is compared to the threshold."
  type        = number
  default     = 1
}

variable "alarm_threshold" {
  description = "Number of matching events in a period that triggers the alarm."
  type        = number
  default     = 1
}

variable "enable_ok_actions" {
  description = "Also notify the SNS topic when an alarm returns to OK."
  type        = bool
  default     = false
}

variable "create_sns_topic" {
  description = "Create a dedicated SNS topic for CIS alerts. When false, existing_sns_topic_arn must be set."
  type        = bool
  default     = true
}

variable "sns_topic_name" {
  description = "Name of the SNS topic created when create_sns_topic is true."
  type        = string
  default     = "cis-benchmark-alerts"
}

variable "existing_sns_topic_arn" {
  description = "ARN of an existing SNS topic used when create_sns_topic is false."
  type        = string
  default     = null
}

variable "sns_kms_master_key_id" {
  description = "Customer managed KMS key (ID, ARN or alias) used to encrypt the SNS topic. CloudWatch alarms cannot publish to a topic encrypted with the AWS managed aws/sns key, so a CMK whose policy allows cloudwatch.amazonaws.com is required."
  type        = string
  default     = null
}

variable "alert_email_endpoints" {
  description = "E-mail addresses subscribed to the SNS topic (each one must confirm the subscription)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.alert_email_endpoints : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "alert_email_endpoints must contain valid e-mail addresses."
  }
}

variable "enable_sns_archiver" {
  description = "Deploy a Lambda function that archives every SNS alert as a JSON object in S3."
  type        = bool
  default     = false
}

variable "archive_bucket_name" {
  description = "Existing S3 bucket that receives archived alerts (required when enable_sns_archiver is true)."
  type        = string
  default     = null
}

variable "archive_prefix" {
  description = "Key prefix used for archived alerts."
  type        = string
  default     = "cis-alerts/"
}

variable "lambda_log_retention_days" {
  description = "Retention of the archiver Lambda log group."
  type        = number
  default     = 365
}

variable "lambda_log_kms_key_arn" {
  description = "Optional KMS key ARN used to encrypt the archiver Lambda log group."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to taggable resources. The landing zone tag policy only accepts: environment, owner, createdby, account."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.tags) : contains(["environment", "owner", "createdby", "account"], k)])
    error_message = "Only the tag keys environment, owner, createdby and account are allowed by the landing zone tag policy."
  }
}
