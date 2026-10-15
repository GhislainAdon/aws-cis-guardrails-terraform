# aws-cis-guardrails-terraform

[![ci](https://github.com/GhislainAdon/aws-cis-guardrails-terraform/actions/workflows/ci.yml/badge.svg)](https://github.com/GhislainAdon/aws-cis-guardrails-terraform/actions/workflows/ci.yml)
![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.5-7B42BC)
![AWS provider](https://img.shields.io/badge/aws%20provider-6.x-FF9900)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Terraform modules that harden an AWS Control Tower / Account Factory for
Terraform (AFT) landing zone against the **CIS AWS Foundations Benchmark**:
monitoring alarms, automatic remediation, Security Hub standards and the AWS
Support role.

> **Disclaimer.** Rewritten from scratch for portfolio purposes; contains no
> client code, identifiers or data. Account IDs, e-mail addresses and names are
> placeholders (`123456789012`, `security@example.com`).

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Modules](#modules)
- [CIS control mapping](#cis-control-mapping)
- [Usage](#usage)
- [Quality gates](#quality-gates)
- [Case study: from 16 copy-pasted modules to one data-driven module](#case-study-from-16-copy-pasted-modules-to-one-data-driven-module)
- [Results](#results)
- [Résumé en français](#résumé-en-français)

## Purpose

In 2025 I spent six months (July to December) as a DevOps engineer on a
consulting engagement, hardening a multi-account landing zone built on AWS
Control Tower and AFT. The target was the CIS AWS Foundations Benchmark as
scored by AWS Security Hub. This repository is a clean-room rewrite of the
patterns I used. It is generic enough to drop into any Control Tower setup:

| Guardrail | CIS | Module |
|-----------|-----|--------|
| Log metric filters and alarms on the organization CloudTrail | 4.1 to 4.15 | [`cis-cloudwatch-alarms`](modules/cis-cloudwatch-alarms) |
| Detect and fix network ACLs exposing SSH/RDP to the internet | 5.1 (NACL) | [`nacl-admin-port-remediation`](modules/nacl-admin-port-remediation) |
| Security Hub enablement and standards (CIS, AWS FSBP) | scoring | [`security-hub`](modules/security-hub) |
| IAM role for managing incidents with AWS Support | 1.17 | [`support-role`](modules/support-role) |

## Architecture

```mermaid
flowchart LR
  subgraph Member["Any enrolled account"]
    NACL[(Network ACL)] -->|configuration change| CFG[AWS Config rule<br/>NACL_NO_UNRESTRICTED_SSH_RDP]
    CFG -->|Compliance Change<br/>NON_COMPLIANT| EB[EventBridge rule]
    EB --> LREM[Lambda<br/>remediation.py]
    LREM -->|delete / shadow with DENY| NACL
    LREM --> SNSR[SNS<br/>remediation reports]
    SH[Security Hub<br/>CIS + FSBP standards]
    ROLE[IAM role<br/>AWSSupportAccess]
  end

  subgraph Mgmt["Account owning the organization trail"]
    CT[Organization CloudTrail] --> LG[(CloudWatch Logs<br/>aws-controltower/CloudTrailLogs)]
    LG --> MF[15 metric filters<br/>namespace CISBenchmark]
    MF --> AL[15 CloudWatch alarms]
    AL --> SNSA[SNS<br/>cis-benchmark-alerts]
    SNSA --> ARCH[Lambda archiver<br/>optional]
    ARCH --> S3[(S3 archive)]
  end

  SNSA --> MAIL[[security@example.com]]
  SNSR --> MAIL
  CFG -. findings .-> SH
```

More detail (data flows, IAM, design decisions) in
[docs/architecture.md](docs/architecture.md).

## Modules

| Module | What it creates |
|--------|-----------------|
| [`cis-cloudwatch-alarms`](modules/cis-cloudwatch-alarms) | One metric filter and one alarm per selected CIS 4.x control (`for_each` over a data model in `locals.tf`), an SNS topic with a least-privilege topic policy and e-mail subscriptions, and an optional SNS to S3 archiver Lambda. Outputs are maps keyed by control ID. |
| [`nacl-admin-port-remediation`](modules/nacl-admin-port-remediation) | AWS managed Config rule, EventBridge rule on `NON_COMPLIANT` evaluations, Python 3.12 Lambda (least-privilege role, X-Ray, log retention), SNS topic. Narrow world-open entries on 22/3389 are deleted; broad ones are shadowed with DENY entries so legitimate traffic is preserved. Dry-run supported. |
| [`security-hub`](modules/security-hub) | `aws_securityhub_account` (optional), standards subscriptions from a list (`for_each`), optional member accounts. |
| [`support-role`](modules/support-role) | IAM role trusted by explicit principals only (wildcards rejected), MFA condition, `AWSSupportAccess` attached. |

Every module accepts a `tags` map that is **validated against the four keys the
landing zone tag policy allows**: `environment`, `owner`, `createdby`,
`account`. Anything else fails at `plan` time instead of at `apply` time.

## CIS control mapping

All patterns are evaluated on the organization CloudTrail log group. Alarms fire
when the metric is `>= 1` over 5 minutes (configurable).

| Control | Detects | Filter pattern (summary) | Severity |
|---------|---------|--------------------------|----------|
| 4.1  | Unauthorized API calls | `errorCode` `*UnauthorizedOperation` or `AccessDenied*`, excluding log delivery and `HeadBucket` noise | MEDIUM |
| 4.2  | Console sign-in without MFA | successful `ConsoleLogin` by an IAM user with `MFAUsed != Yes` | HIGH |
| 4.3  | Root account usage | `userIdentity.type = Root`, not invoked by a service, not an `AwsServiceEvent` | CRITICAL |
| 4.4  | IAM policy changes | 16 `Put/Delete/Attach/Detach/Create*Policy*` events | HIGH |
| 4.5  | CloudTrail configuration changes | `Create/Update/DeleteTrail`, `Start/StopLogging` | CRITICAL |
| 4.6  | Console authentication failures | `ConsoleLogin` with `Failed authentication` | MEDIUM |
| 4.7  | CMK disabled or scheduled for deletion | `kms.amazonaws.com`: `DisableKey`, `ScheduleKeyDeletion` | HIGH |
| 4.8  | S3 bucket policy changes | `s3.amazonaws.com`: ACL, policy, CORS, lifecycle, replication puts/deletes | HIGH |
| 4.9  | AWS Config changes | `config.amazonaws.com`: stop recorder, put/delete delivery channel, put recorder | HIGH |
| 4.10 | Security group changes | authorize/revoke ingress/egress, create/delete security group | MEDIUM |
| 4.11 | Network ACL changes | create/delete/replace NACL and entries, replace association | MEDIUM |
| 4.12 | Network gateway changes | customer gateway and internet gateway lifecycle | MEDIUM |
| 4.13 | Route table changes | `ec2.amazonaws.com`: create/replace/delete route and route table, (dis)associate | MEDIUM |
| 4.14 | VPC changes | VPC create/delete/modify, peering lifecycle, ClassicLink | MEDIUM |
| 4.15 | AWS Organizations changes | `organizations.amazonaws.com`: accounts, OUs, policies, handshakes | HIGH |

The exact patterns are in
[`modules/cis-cloudwatch-alarms/locals.tf`](modules/cis-cloudwatch-alarms/locals.tf)
and are exposed through the `controls` output. Patterns made only of event names
are generated from an `event_source` + `event_names` list, so they cannot drift
in syntax.

## Usage

```hcl
module "cis_alarms" {
  source = "github.com/GhislainAdon/aws-cis-guardrails-terraform//modules/cis-cloudwatch-alarms?ref=v1.0.0"

  cloudtrail_log_group_name = "aws-controltower/CloudTrailLogs"
  alert_email_endpoints     = ["security@example.com"]
  enabled_controls          = null # all 15; or ["4.1", "4.3", "4.5"]

  tags = {
    environment = "production"
    owner       = "platform-team"
    createdby   = "terraform"
    account     = "123456789012"
  }
}

output "alarms" {
  value = module.cis_alarms.alarm_names # { "4.1" = "lz-CIS-4.1-UnauthorizedAPICalls", ... }
}
```

A runnable composition of the four modules is in
[`examples/complete`](examples/complete):

```bash
cd examples/complete
cp terraform.tfvars.example terraform.tfvars   # adjust, file is git-ignored
terraform init
terraform plan
```

Offline checks (no AWS credentials needed):

```bash
terraform fmt -check -recursive
for d in modules/* examples/complete; do (cd "$d" && terraform init -backend=false && terraform validate && terraform test); done
python -m unittest discover -s modules/nacl-admin-port-remediation/tests
python -m unittest discover -s modules/cis-cloudwatch-alarms/tests
```

## Quality gates

| Gate | Local (pre-commit) | CI (`.github/workflows/ci.yml`) |
|------|--------------------|---------------------------------|
| Formatting | `terraform_fmt` | `terraform fmt -check -recursive` |
| Validation | `terraform_validate` | `init -backend=false` + `validate` per module and example |
| Plan-level tests | - | `terraform test` with mocked providers |
| Lint | `terraform_tflint` (`.tflint.hcl`, AWS ruleset) | `tflint --recursive` |
| Security | `terraform_checkov` | `bridgecrewio/checkov-action` |
| Docs | `terraform_docs` | - |
| Secrets | `detect-private-key`, `detect-aws-credentials`, `gitleaks` | gitleaks container |
| Lambda logic | - | `python -m unittest` (no boto3, no AWS) |
| Commit messages | `commitlint` (commit-msg stage) | `commitlint` on pull requests |

Checkov findings that do not apply are skipped **inline with a justification**
(for example `CKV_AWS_26`: CloudWatch alarms cannot publish to a topic encrypted
with the AWS managed `aws/sns` key, so encryption takes a caller-supplied CMK).

## Case study: from 16 copy-pasted modules to one data-driven module

### Starting point

The first implementation of CIS monitoring followed a "one module per control"
layout: 16 near-identical modules, each with its own nested `sns`, `cloudwatch`
and `lambda` submodules. Adding or fixing a control meant editing the same code
in 16 places, reviews were long, and drift between controls was already
visible.

### Problems and fixes

| # | Problem | Root cause | Fix |
|---|---------|------------|-----|
| 1 | Same logic duplicated 16 times (16 modules x 3 submodules) | One module per control | A single module where controls are **data** (`locals.tf`) and resources use `for_each`. A new control is a new map entry. |
| 2 | Deep nesting (`module.x.module.sns...`) hard to read and review | Submodules per concern | **Flat files** inside one module: `main.tf`, `sns.tf`, `archiver.tf`, `locals.tf`. |
| 3 | `Unsupported attribute` errors on outputs once `for_each` was introduced | Outputs still referenced a single instance | **Map outputs** keyed by control ID: `{ for id, a in aws_cloudwatch_metric_alarm.this : id => a.arn }`. |
| 4 | `terraform validate` failed locally: missing provider configuration for an aliased provider (`aws.eu_central_1`) | AFT renders provider blocks inside the pipeline only | **Local-only `*_override.tf` provider file**, git-ignored, never committed; modules declare no provider blocks. |
| 5 | `apply` rejected by the organization tag policy | Modules added tags such as `Project`, `CIS_Control`, `created_by` | **Tag cleanup** to the four allowed keys, now enforced by a `validation` block on `var.tags` in every module. |
| 6 | `BucketAlreadyOwnedByYou` on the state bucket | A bucket left over from an earlier test run | **`terraform import`** of the existing bucket into state instead of deleting and recreating it. |
| 7 | tflint `terraform_unused_declarations` on variables kept "for compatibility" | Dead inputs | At the time, a workaround echoed them in outputs. In this rewrite they are simply gone: the module API is only what is used. |

Details and snippets: [docs/lessons-learned.md](docs/lessons-learned.md).

## Results

- **15 metric filters + 15 alarms + 1 SNS topic** deployed in the management
  account on the Control Tower CloudTrail log group, namespace `CISBenchmark`.
- **16 per-control modules x 3 submodules consolidated into 1 module**: one
  place to review, one set of outputs, selectable controls.
- **18 security deliverables across 18 feature branches in about one month**
  (CIS monitoring, NACL remediation, Security Hub, support role and related
  account customizations), each going through the same validation pipeline.
- Tag-policy violations moved from `apply`-time failures in the pipeline to
  `plan`-time validation errors on the developer's machine.

## Repository layout

```text
.
├── modules/
│   ├── cis-cloudwatch-alarms/        # CIS 4.1-4.15 (data-driven) + SNS + optional archiver
│   ├── nacl-admin-port-remediation/  # Config rule -> EventBridge -> Lambda -> SNS
│   ├── security-hub/                 # account, standards, members
│   └── support-role/                 # CIS 1.17
├── examples/complete/                # all modules with placeholder values
├── docs/                             # architecture, lessons learned
└── .github/workflows/ci.yml
```

## Résumé en français

Ce dépôt regroupe des modules Terraform qui renforcent une landing zone AWS
Control Tower / AFT selon le **CIS AWS Foundations Benchmark**. Il s'agit d'une
réécriture complète, réalisée pour mon portfolio, du travail effectué lors d'une
mission de conseil DevOps de six mois (juillet à décembre 2025). Il ne contient
aucun code, identifiant ni donnée client.

- **`cis-cloudwatch-alarms`** : les 15 contrôles CIS 4.x décrits comme des
  données (`locals.tf`) et déployés par `for_each` (filtres de métriques +
  alarmes dans l'espace de noms `CISBenchmark`), sélection des contrôles,
  sorties sous forme de maps, topic SNS avec abonnements e-mail et archivage
  optionnel vers S3.
- **`nacl-admin-port-remediation`** : règle AWS Config
  `NACL_NO_UNRESTRICTED_SSH_RDP`, EventBridge, Lambda Python qui supprime ou
  neutralise (règles DENY) les entrées NACL ouvrant 22/3389 à Internet, puis
  notification SNS. Mode simulation disponible, tests unitaires sans AWS.
- **`security-hub`** : activation, souscription aux standards, comptes membres.
- **`support-role`** : rôle IAM CIS 1.17 avec MFA et `AWSSupportAccess`.

**Étude de cas** : 16 modules copiés-collés (chacun avec 3 sous-modules) ont été
remplacés par un seul module piloté par les données. Les problèmes rencontrés
(sorties cassées avec `for_each`, providers AFT absents en local, tags refusés
par la tag policy, bucket d'état déjà existant) ont été résolus respectivement
par des sorties en map, des fichiers `*_override.tf` locaux non versionnés, un
nettoyage des tags (4 clés autorisées, validées dans chaque module) et
`terraform import`.

**Résultats** : 15 filtres + 15 alarmes + SNS déployés dans le compte de
management ; 18 livrables sécurité sur 18 branches en un mois environ ;
16 modules x 3 sous-modules consolidés en 1 module.

## License

[MIT](LICENSE) © Ghislain Adon
