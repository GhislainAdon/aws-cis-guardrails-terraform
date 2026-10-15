# cis-cloudwatch-alarms

CloudWatch Logs metric filters and alarms for the CIS AWS Foundations Benchmark
monitoring section (controls 4.1 to 4.15), built on the organization CloudTrail
log group of a Control Tower landing zone.

- Controls are data (`locals.tf`); resources iterate with `for_each`.
- `enabled_controls` selects a subset (`null` = all 15).
- Outputs are maps keyed by control ID (`"4.1"` ... `"4.15"`).
- SNS topic with a confused-deputy-safe topic policy and e-mail subscriptions,
  or bring your own topic (`create_sns_topic = false`).
- Optional SNS to S3 archiver Lambda (`enable_sns_archiver = true`).

## Usage

```hcl
module "cis_alarms" {
  source = "../../modules/cis-cloudwatch-alarms"

  cloudtrail_log_group_name = "aws-controltower/CloudTrailLogs"
  alert_email_endpoints     = ["security@example.com"]
  enabled_controls          = ["4.1", "4.2", "4.3", "4.5", "4.7"]
  sns_kms_master_key_id     = "alias/cis-alerts" # CMK allowing cloudwatch.amazonaws.com

  tags = {
    environment = "production"
    owner       = "platform-team"
    createdby   = "terraform"
    account     = "123456789012"
  }
}
```

## Tests

```bash
terraform init -backend=false && terraform test        # plan-level, mocked AWS provider
python -m unittest discover -s tests                   # archiver Lambda
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
| cloudtrail_log_group_name | Existing CloudWatch Logs group receiving the organization trail | `string` | n/a | yes |
| name_prefix | Prefix for metric filter and alarm names | `string` | `"lz"` | no |
| metric_namespace | CloudWatch metric namespace | `string` | `"CISBenchmark"` | no |
| enabled_controls | CIS 4.x control IDs to deploy; `null` = all | `list(string)` | `null` | no |
| alarm_period | Evaluation period in seconds | `number` | `300` | no |
| alarm_evaluation_periods | Periods compared to the threshold | `number` | `1` | no |
| alarm_threshold | Matching events that trigger the alarm | `number` | `1` | no |
| enable_ok_actions | Also notify on return to OK | `bool` | `false` | no |
| create_sns_topic | Create the alert topic | `bool` | `true` | no |
| sns_topic_name | Name of the created topic | `string` | `"cis-benchmark-alerts"` | no |
| existing_sns_topic_arn | Topic used when `create_sns_topic = false` | `string` | `null` | no |
| sns_kms_master_key_id | CMK for the topic (aws/sns is not usable by CloudWatch) | `string` | `null` | no |
| alert_email_endpoints | E-mail subscribers | `list(string)` | `[]` | no |
| enable_sns_archiver | Deploy the SNS to S3 archiver | `bool` | `false` | no |
| archive_bucket_name | Existing archive bucket | `string` | `null` | no |
| archive_prefix | Archive key prefix | `string` | `"cis-alerts/"` | no |
| lambda_log_retention_days | Archiver log retention | `number` | `365` | no |
| lambda_log_kms_key_arn | KMS key for the archiver log group | `string` | `null` | no |
| tags | Tags (only environment, owner, createdby, account) | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| enabled_controls | Deployed control IDs |
| metric_filter_names | Control ID => metric filter name |
| alarm_names | Control ID => alarm name |
| alarm_arns | Control ID => alarm ARN |
| controls | Control ID => title, severity, pattern |
| sns_topic_arn | Alert topic ARN |
| archiver_function_arn | Archiver Lambda ARN (or null) |
<!-- END_TF_DOCS -->
