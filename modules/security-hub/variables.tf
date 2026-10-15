variable "enable_security_hub" {
  description = "Enable Security Hub in the current account. Set to false when the account is already enabled by a delegated administrator (Organizations auto-enable)."
  type        = bool
  default     = true
}

variable "enable_default_standards" {
  description = "Let Security Hub subscribe to its default standards. Keep false so that var.standards is the single source of truth."
  type        = bool
  default     = false
}

variable "control_finding_generator" {
  description = "SECURITY_CONTROL (consolidated control findings) or STANDARD_CONTROL (one finding per standard)."
  type        = string
  default     = "SECURITY_CONTROL"

  validation {
    condition     = contains(["SECURITY_CONTROL", "STANDARD_CONTROL"], var.control_finding_generator)
    error_message = "control_finding_generator must be SECURITY_CONTROL or STANDARD_CONTROL."
  }
}

variable "auto_enable_controls" {
  description = "Automatically enable new controls when they are added to subscribed standards."
  type        = bool
  default     = true
}

variable "standards" {
  description = "Standards to subscribe to, as the path after 'standards/' (or 'ruleset/...' for CIS 1.2.0)."
  type        = list(string)
  default = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/3.0.0",
  ]

  validation {
    condition     = alltrue([for s in var.standards : can(regex("^(ruleset/)?[a-z0-9-]+/v/[0-9.]+$", s))])
    error_message = "Each standard must look like 'cis-aws-foundations-benchmark/v/3.0.0'."
  }
}

variable "members" {
  description = "Member accounts to associate when this account is the Security Hub administrator: map of account ID => root e-mail address."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for id in keys(var.members) : can(regex("^[0-9]{12}$", id))])
    error_message = "members keys must be 12-digit AWS account IDs."
  }
}

variable "invite_members" {
  description = "Send an invitation to member accounts. Leave false inside AWS Organizations, where membership is automatic."
  type        = bool
  default     = false
}
