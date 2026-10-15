# support-role

CIS AWS Foundations Benchmark 1.17: "Ensure a support role has been created to
manage incidents with AWS Support" (Security Hub control IAM.18).

Creates an IAM role with the AWS managed `AWSSupportAccess` policy, trusted only
by explicit principals (wildcards are rejected by validation) and, by default,
only when MFA is present.

## Usage

```hcl
module "support_role" {
  source = "../../modules/support-role"

  trusted_principal_arns = ["arn:aws:iam::123456789012:role/platform-security-engineers"]
  tags                   = { environment = "production", owner = "platform-team" }
}
```

Note: when the trusted principal is itself an assumed role (for example an IAM
Identity Center permission set), the MFA context key is not propagated through
role chaining. Enforce MFA at the identity provider and set
`require_mfa = false` in that case.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 6.0, < 7.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| trusted_principal_arns | Principals allowed to assume the role | `list(string)` | n/a | yes |
| role_name | Role name | `string` | `"aws-support-incident-role"` | no |
| role_path | IAM path | `string` | `"/"` | no |
| require_mfa | Require MFA in the trust policy | `bool` | `true` | no |
| max_session_duration | Max session duration (s) | `number` | `3600` | no |
| permissions_boundary_arn | Optional permissions boundary | `string` | `null` | no |
| tags | Tags (only environment, owner, createdby, account) | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| role_name | Role name |
| role_arn | Role ARN |
| attached_policy_arn | ARN of AWSSupportAccess |
<!-- END_TF_DOCS -->
