# nacl-admin-port-remediation

Detects and fixes network ACLs that expose administration ports (SSH 22, RDP
3389) to `0.0.0.0/0` or `::/0` (CIS AWS Foundations Benchmark 5.1).

```text
AWS Config (NACL_NO_UNRESTRICTED_SSH_RDP)
  -> EventBridge (Config Rules Compliance Change, NON_COMPLIANT)
    -> Lambda remediation.py
      -> EC2: delete narrow entry | insert DENY entries ahead of broad entry
      -> SNS report
```

| Offending inbound ALLOW entry | Action |
|-------------------------------|--------|
| Covers only admin ports (e.g. TCP 22-22) | deleted |
| All traffic or wide port range | DENY entries for 22/3389 inserted at lower rule numbers |
| No free rule number available | nothing changed, `manual_action_required` reported |

Prerequisite: an active AWS Config configuration recorder (Control Tower
provides one in every enrolled account).

## Usage

```hcl
module "nacl_remediation" {
  source = "../../modules/nacl-admin-port-remediation"

  dry_run               = true # start in report-only mode
  alert_email_endpoints = ["security@example.com"]
  tags                  = { environment = "production", owner = "platform-team" }
}
```

## Tests

```bash
python -m unittest discover -s tests -v   # no AWS account, no boto3, no moto
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 6.0, < 7.0 |
| archive | >= 2.4 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name_prefix | Prefix for resource names | `string` | `"lz"` | no |
| create_config_rule | Create the managed Config rule | `bool` | `true` | no |
| config_rule_name | Config rule name watched by EventBridge | `string` | `"nacl-no-unrestricted-ssh-rdp"` | no |
| admin_ports | Ports that must not be world-reachable | `list(number)` | `[22, 3389]` | no |
| dry_run | Report only | `bool` | `false` | no |
| alert_email_endpoints | E-mail subscribers | `list(string)` | `[]` | no |
| sns_kms_master_key_id | KMS key for the topic | `string` | `"alias/aws/sns"` | no |
| lambda_log_retention_days | Log retention | `number` | `365` | no |
| lambda_log_kms_key_arn | KMS key for the log group | `string` | `null` | no |
| tags | Tags (only environment, owner, createdby, account) | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| config_rule_name | Watched Config rule |
| config_rule_arn | Config rule ARN (or null) |
| event_rule_arn | EventBridge rule ARN |
| lambda_function_arn | Remediation Lambda ARN |
| lambda_role_arn | Lambda role ARN |
| sns_topic_arn | Report topic ARN |
<!-- END_TF_DOCS -->
