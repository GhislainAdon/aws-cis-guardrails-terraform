# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-16

### Added

- `modules/cis-cloudwatch-alarms`: the 15 CIS 4.x monitoring controls described
  as data in `locals.tf`, deployed with `for_each` (metric filters + alarms in
  the `CISBenchmark` namespace), selectable through `enabled_controls`, map
  outputs keyed by control ID, SNS topic with e-mail subscriptions and a scoped
  topic policy, optional SNS to S3 archiver Lambda.
- `modules/nacl-admin-port-remediation`: AWS Config rule
  `NACL_NO_UNRESTRICTED_SSH_RDP`, EventBridge routing of `NON_COMPLIANT`
  evaluations, Python remediation Lambda (delete narrow entries, shadow broad
  ones with DENY entries, dry-run mode) and SNS reporting.
- `modules/security-hub`: account enablement, standards subscriptions driven by
  a list, optional member accounts.
- `modules/support-role`: CIS 1.17 AWS Support role with MFA-protected trust
  policy and `AWSSupportAccess`.
- `examples/complete` wiring the four modules with placeholder values.
- Offline `terraform test` suites (mocked providers) and Python `unittest`
  suites for both Lambda functions.
- Quality toolchain: pre-commit (fmt, validate, tflint, terraform-docs,
  checkov, gitleaks, secret detection), tflint ruleset, commitlint, GitHub
  Actions CI.
- Documentation: README, architecture, lessons learned.
