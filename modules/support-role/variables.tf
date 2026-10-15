variable "role_name" {
  description = "Name of the IAM role used to manage incidents with AWS Support."
  type        = string
  default     = "aws-support-incident-role"
}

variable "role_path" {
  description = "IAM path of the role."
  type        = string
  default     = "/"
}

variable "trusted_principal_arns" {
  description = "IAM principals (roles, users or account roots) allowed to assume the support role. Wildcards are rejected."
  type        = list(string)

  validation {
    condition = length(var.trusted_principal_arns) > 0 && alltrue([
      for a in var.trusted_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(root|role/.+|user/.+)$", a)) && !strcontains(a, "*")
    ])
    error_message = "trusted_principal_arns must contain at least one explicit IAM principal ARN without wildcards."
  }
}

variable "require_mfa" {
  description = "Require MFA in the trust policy. Disable only when the trusted principals are federated roles whose IdP already enforces MFA (MFA context is not propagated through role chaining)."
  type        = bool
  default     = true
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds (3600-43200)."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 3600 and 43200 seconds."
  }
}

variable "permissions_boundary_arn" {
  description = "Optional permissions boundary attached to the role."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to the role. The landing zone tag policy only accepts: environment, owner, createdby, account."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.tags) : contains(["environment", "owner", "createdby", "account"], k)])
    error_message = "Only the tag keys environment, owner, createdby and account are allowed by the landing zone tag policy."
  }
}
