# Example: complete

Deploys the four guardrails in one account with placeholder values
(account `123456789012`, region `eu-west-3`, mailbox `security@example.com`,
log group `aws-controltower/CloudTrailLogs`).

```bash
cp terraform.tfvars.example terraform.tfvars   # git-ignored
terraform init
terraform plan
```

The NACL remediation starts in **dry-run** mode (`remediation_dry_run = true`):
it reports what it would change without touching any network ACL.

Offline test of the whole composition (mocked providers, no credentials):

```bash
terraform init -backend=false
terraform test
```
