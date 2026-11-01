# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] (unreleased)

v2 is a drop-in replacement for v0.4.0: the same Terraform module, `Event` log
field names and `SLACK_*` variables, and the embedded default policy makes the
same filtering decisions apart from the changes listed below.

### Changed

- **Declarative policy engine replaces the hardcoded filter.** Filtering is
  driven by a FilterPolicy YAML document ([schema](./policy.schema.json)). The
  v0.4.0 ruleset is embedded as the default and can be overridden with
  `--config-file` / `CCA_POLICY_FILE` without recompiling.
- **Log format** is slog-style (`"level":"INFO"`) instead of logrus-style
  (`"level":"info"`). The `Event` line keeps `msg == "Event"` and every v0
  field name, with two value changes: `event_name` is the raw event name
  (v0 logged the Slack text, `*PutUserPolicy*` or `3x *PutUserPolicy*`), and
  `event_time` is the record's RFC 3339 `eventTime` (v0 logged a display
  string such as `2026-07-07 12:00:00 ... 13:30:00`). New fields:
  `aws_region`, `error_code` and `identity_account_id`.
- **CloudShell lifecycle events** (`CreateEnvironment`, `CreateSession`,
  `DeleteEnvironment`, ...) are dropped only from CloudShell. v0 dropped those
  names from every service, hiding console actions such as Elastic Beanstalk
  `CreateEnvironment` and Glue `CreateSession`.
- **Deduplication** groups by `(account, eventSource, userName, eventName,
  errorCode)`, so the same user and action in different accounts or services
  alert separately. It can be disabled with `--dedupe` / `CCA_DEDUPE`, and
  flush order is deterministic.
- **CloudTrail Insights files** (`CloudTrail-Insight/`) are ignored.
- **Slack failures** are logged at error level instead of debug.
- Built with Go 1.27 and the AWS SDK for Go v2.

### Added

- An opt-in `keep` rule, shipped commented out in the default policy, that
  alerts on writes disabling logging or detection (CloudTrail trails and
  event selectors, GuardDuty, Security Hub, AWS Config, VPC flow logs) and
  `PutUserPolicy` from any user agent, CLI and IaC included.
- `--validate-only` and `--dump-default-policy` flags.
- Per-record decision tracing at `LOG_LEVEL=debug`.
- [Policy language reference](./docs/policy-language.md).
- Slack delivery retries 429 and 5xx responses, honouring `Retry-After`,
  within the invocation deadline.
- Terraform: optional `logs` variable to manage the Lambda log group
  (retention, class, KMS key) in Terraform.
- Terraform: optional `policy` variable that deploys a custom FilterPolicy as
  a Lambda layer; unset keeps the embedded default.
- Terraform: the modules declare their minimum versions (Terraform 1.3, AWS
  provider 6.0, archive provider 2.4).
- Release workflow: tagged releases publish `function_arm64.zip`,
  `function_amd64.zip` and `sha256sums.txt`.

### Fixed

- The Slack payload is marshalled instead of string-interpolated, so values
  containing quotes no longer break the message, and record-derived text is
  mrkdwn-escaped.
- Slack console deep-link parameters are URL-encoded, so assumed-role and SSO
  principals no longer break the link.
- Grouped Slack time windows spanning a month boundary show both dates.
- The Slack webhook URL is never written to the logs.
- Malformed or non-CloudTrail S3 objects are logged and skipped instead of
  failing (and endlessly retrying) the invocation, and a single undecodable
  record skips only that record instead of the whole file.
- S3 object keys are URL-decoded; SNS- and SQS-wrapped events take the
  bucket's region from the S3 record; `s3:TestEvent` messages no longer fail
  the batch.
- Terraform: the IAM `logs:CreateLogGroup` resource ARN was missing its
  `log-group:` segment, so the permission never applied.
- Terraform: the S3 example module plans and applies cleanly (module source
  paths and artifact filename).

### Upgrading

Point the Terraform module at the v2 artifact. To start managing an existing
log group with `logs = { create = true }`, import it first:

```bash
terraform import 'module.default.aws_cloudwatch_log_group.default[0]' /aws/lambda/<name>
```
