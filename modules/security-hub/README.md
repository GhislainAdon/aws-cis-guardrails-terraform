# security-hub

Enables AWS Security Hub, subscribes to a list of standards and optionally
associates member accounts.

## Usage

```hcl
module "security_hub" {
  source = "../../modules/security-hub"

  standards = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/3.0.0",
  ]
}
```

In an AWS Organizations setup with a delegated administrator, set
`enable_security_hub = false` in accounts that are auto-enabled, and leave
`members` empty: membership is managed by the organization.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 6.0, < 7.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_security_hub | Create `aws_securityhub_account` | `bool` | `true` | no |
| enable_default_standards | Let Security Hub add its defaults | `bool` | `false` | no |
| control_finding_generator | `SECURITY_CONTROL` or `STANDARD_CONTROL` | `string` | `"SECURITY_CONTROL"` | no |
| auto_enable_controls | Auto-enable new controls | `bool` | `true` | no |
| standards | Standard paths (after `standards/`, or `ruleset/...`) | `list(string)` | FSBP 1.0.0, CIS 3.0.0 | no |
| members | Account ID => e-mail | `map(string)` | `{}` | no |
| invite_members | Send invitations | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| securityhub_account_id | Security Hub account resource ID (or null) |
| standards_arns | Standard path => ARN |
| standards_subscription_ids | Standard path => subscription ID |
| member_ids | Account ID => member resource ID |
<!-- END_TF_DOCS -->
