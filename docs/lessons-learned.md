# Lessons learned

Notes from hardening a Control Tower / AFT landing zone against the CIS AWS
Foundations Benchmark. Every snippet below is generic and rewritten for this
repository.

## 1. Model controls as data, not as modules

**Before:** one module per CIS control, each wrapping `sns`, `cloudwatch` and
`lambda` submodules: 16 x 3 directories with the same code and different
strings.

**After:** a single map in `locals.tf` and two `for_each` resources.

```hcl
locals {
  cis_controls = {
    "4.7" = {
      slug         = "CMKDisableOrScheduledDeletion"
      title        = "Disabling or scheduled deletion of customer managed keys"
      severity     = "HIGH"
      event_source = "kms.amazonaws.com"
      event_names  = ["DisableKey", "ScheduleKeyDeletion"]
      pattern      = null
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = local.controls
  # ...
}
```

What it bought us: one review instead of sixteen, a uniform naming convention,
the ability to select controls per environment, and resource addresses that
read like the benchmark (`aws_cloudwatch_metric_alarm.this["4.7"]`).

Migration tip: when moving from per-control modules to `for_each`, use
`moved` blocks (or `terraform state mv`) so existing alarms are not destroyed
and recreated:

```hcl
moved {
  from = module.cis_4_7.module.cloudwatch.aws_cloudwatch_metric_alarm.this
  to   = module.cis_alarms.aws_cloudwatch_metric_alarm.this["4.7"]
}
```

## 2. Flatten before you abstract

Nested submodules (`module.a.module.b.module.c`) look tidy but make plans and
error messages hard to read and force every value through three layers of
variables and outputs. Splitting one module into **flat files** (`main.tf`,
`sns.tf`, `archiver.tf`, `locals.tf`) gave the same separation of concerns with
none of the plumbing.

## 3. `for_each` changes the shape of outputs

Once a resource or module uses `for_each`, it is a map of instances. Outputs
written for a single instance fail with `Unsupported attribute`. Expose maps
keyed by the same key:

```hcl
output "alarm_arns" {
  value = { for id, a in aws_cloudwatch_metric_alarm.this : id => a.arn }
}
```

Callers then write `module.cis_alarms.alarm_arns["4.3"]`, which is explicit and
stable when controls are added or removed.

## 4. AFT-generated providers do not exist on your laptop

AFT renders `provider` and `backend` blocks inside its pipeline. Customization
code that references an aliased provider (for example a second region alias
such as `aws.eu_central_1`) fails locally with "missing provider configuration".

What worked:

- Modules never declare `provider` blocks; they only declare
  `required_providers` (and `configuration_aliases` when an alias is needed).
- Developers keep a **local-only override file**, git-ignored by the
  `*_override.tf` rule in `.gitignore`:

```hcl
# providers_override.tf  (never committed)
provider "aws" {
  region  = "eu-west-3"
  profile = "sandbox"
}

provider "aws" {
  alias   = "eu_central_1"
  region  = "eu-central-1"
  profile = "sandbox"
}
```

- CI runs `terraform init -backend=false` and `terraform validate`, plus
  `terraform test` with **mocked providers**, so no credentials are needed to
  catch most mistakes before the AFT pipeline does.

## 5. Tag policies fail late; validate early

The organization tag policy accepted only `environment`, `owner`, `createdby`
and `account`. Modules that added `Project`, `CIS_Control`, `AlertType` or a
second spelling such as `created_by` passed `validate` and `plan`, then failed
during `apply` in the pipeline.

Fix in two steps: remove the extra tags, then make the rule executable so it
cannot regress:

```hcl
variable "tags" {
  type    = map(string)
  default = {}

  validation {
    condition     = alltrue([for k in keys(var.tags) : contains(["environment", "owner", "createdby", "account"], k)])
    error_message = "Only environment, owner, createdby and account are allowed by the tag policy."
  }
}
```

## 6. Adopt, do not recreate: `terraform import`

A previous test run had already created the state bucket, so the next apply
failed with `BucketAlreadyOwnedByYou`. Deleting a state bucket is never the
right answer. Import it and let Terraform converge:

```bash
terraform import 'module.backend.aws_s3_bucket.state' <existing-bucket-name>
```

or, with Terraform >= 1.5, declaratively:

```hcl
import {
  to = module.backend.aws_s3_bucket.state
  id = "<existing-bucket-name>"
}
```

## 7. Remediation must not cause an outage

A first version of the NACL remediation deleted **every** inbound
`0.0.0.0/0` allow entry. That fixes the finding but can also drop HTTPS on a
public subnet. The rewritten Lambda distinguishes:

| Offending entry | Action |
|-----------------|--------|
| Covers only 22 and/or 3389 | delete it |
| All traffic, or a wide port range | insert DENY 22/3389 at lower rule numbers |
| No free rule number below it | change nothing, report `manual_action_required` |

and ships with a dry-run mode and unit tests on a pure planning function.

## 8. Know the service-to-service encryption limits

- CloudWatch alarms and EventBridge cannot publish to an SNS topic encrypted
  with the AWS managed `aws/sns` key; they need a customer managed key whose
  policy grants the service principal. The alarms module therefore exposes the
  key as an input and documents the Checkov skip instead of silently using
  `aws/sns`.
- A Lambda publishing with its own IAM role is fine with `aws/sns`, so the
  remediation module uses it by default.

## 9. Keep the quality gates boring and identical everywhere

The same checks run in pre-commit and CI: `fmt`, `validate`, `tflint`,
`checkov`, secret detection, `terraform-docs`, conventional commits. Checkov
skips are allowed only inline, next to the resource, with a reason. This made
reviews about design instead of formatting and let many small feature branches
go through quickly.
