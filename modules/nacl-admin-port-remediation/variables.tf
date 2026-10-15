variable "name_prefix" {
  description = "Prefix used for every resource name created by the module."
  type        = string
  default     = "lz"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,32}$", var.name_prefix))
    error_message = "name_prefix must be 1-32 characters: letters, digits, '-' or '_'."
  }
}

variable "create_config_rule" {
  description = "Create the AWS managed Config rule NACL_NO_UNRESTRICTED_SSH_RDP. Set to false if it is already deployed (for example by a conformance pack); config_rule_name must then match it."
  type        = bool
  default     = true
}

variable "config_rule_name" {
  description = "Name of the AWS Config rule whose compliance changes trigger the remediation."
  type        = string
  default     = "nacl-no-unrestricted-ssh-rdp"
}

variable "admin_ports" {
  description = "Administration ports that must never be reachable from 0.0.0.0/0 or ::/0."
  type        = list(number)
  default     = [22, 3389]

  validation {
    condition     = length(var.admin_ports) > 0 && alltrue([for p in var.admin_ports : p >= 0 && p <= 65535])
    error_message = "admin_ports must contain at least one port between 0 and 65535."
  }
}

variable "dry_run" {
  description = "When true the Lambda only reports what it would change."
  type        = bool
  default     = false
}

variable "alert_email_endpoints" {
  description = "E-mail addresses notified of every remediation (each one must confirm the subscription)."
  type        = list(string)
  default     = []
}

variable "sns_kms_master_key_id" {
  description = "KMS key used to encrypt the notification topic. The AWS managed key works here because only the Lambda publishes to it."
  type        = string
  default     = "alias/aws/sns"
}

variable "lambda_log_retention_days" {
  description = "Retention of the remediation Lambda log group."
  type        = number
  default     = 365
}

variable "lambda_log_kms_key_arn" {
  description = "Optional KMS key ARN used to encrypt the Lambda log group."
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
