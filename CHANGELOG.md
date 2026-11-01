# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] — unreleased

### Changed (breaking)

- **Declarative policy engine replaces the hardcoded filter.** Filtering is now
  driven by a FilterPolicy YAML document ([schema](./policy.schema.json)); the
  v1 ruleset (v0.4.0) is embedded as a golden-tested default and can be
  overridden with `--config-file` / `CCA_POLICY_FILE` without recompiling.
- **Log format** is now slog-style (`"level":"INFO"`) instead of logrus-style
  (`"level":"info"`). The `Event` log contract (`msg == "Event"`, field names)
  and all `SLACK_*` variables are unchanged.
- **`keep` rules always emit security writes** — `DeleteTrail`, `StopLogging`,
  `UpdateTrail`, `PutUserPolicy`, `DeleteFlowLogs`, GuardDuty `DeleteDetector`,
  `DisableSecurityHub`, and AWS Config `StopConfigurationRecorder`,
  `DeleteConfigurationRecorder`, `DeleteDeliveryChannel` — even from
  non-console user agents that v1 dropped. Calls AWS makes on your behalf
  (`invokedBy: AWS Internal`) are still dropped.
- **Deduplication** is configurable (`--dedupe` / `CCA_DEDUPE`, default on),
  groups by `(account, eventSource, userName, eventName, errorCode)` — v1
  merged the same user/event across accounts and services — and flush order is
  deterministic. A group's record, outputs and `s3_uri` all describe its most
  recent event.
- **CloudTrail Insights files** (`CloudTrail-Insight/`) are ignored.

### Added

- `--validate-only` and `--dump-default-policy` flags.
- Per-record decision tracing at `LOG_LEVEL=debug`.
- [Policy language reference](./docs/policy-language.md), including `keys()`,
  quoted field names (`requestParameters."x-amz-acl"`) and string escapes.
- Slack delivery retries 429 / 5xx responses (bounded, honouring
  `Retry-After`) within the invocation deadline.

### Fixed

- The Slack webhook URL (a credential) no longer appears in logged errors.
- A connection failure while reading a log file now fails the invocation (so
  it is retried) instead of being logged as a malformed file and skipped.
- The policy loader rejects unknown keys inside `when:` blocks and conditions
  (a typo used to drop the clause silently), duplicate field names, and
  unquoted zero-padded numbers such as `012345670123` (read by YAML as octal).
- `Equals` and set membership compare two strings exactly (`"01"` no longer
  equals `"1"`); unquoted literal values keep their YAML type (`flag: true` is
  a boolean).
- Slack text is mrkdwn-escaped, and time windows spanning a month boundary
  show both dates.
- S3 object keys are URL-decoded; SNS/SQS-wrapped events take the bucket's
  region from the S3 record; `s3:TestEvent` messages no longer fail the batch.
- Hot-path allocations reduced ~20x (per-record numeric coercion no longer
  allocates on non-numeric strings; disabled tracer no longer boxes arguments).
- Slack console deep-link parameters are now URL-encoded (assumed-role / SSO
  principals no longer break the link).
- Malformed / non-CloudTrail S3 objects are logged and skipped instead of
  failing (and endlessly retrying) the whole invocation.
- Terraform: the S3 example module now plans/applies cleanly (correct module
  source paths and artifact filename).
- Terraform: the IAM `logs:CreateLogGroup` resource ARN was missing its
  `log-group:` segment, so the permission never applied.

### Upgrading from v1

Redeploy the same Terraform module against the new artifact (`make zip`
produces `dist/function_arm64.zip`). No policy migration is required — the
embedded default reproduces v1 (v0.4.0) decisions apart from the changes
above. To customize, start from `--dump-default-policy`.

To manage the Lambda's log group in Terraform, set `logs = { create = true }`.
An existing deployment already has an auto-created `/aws/lambda/<name>`
group, so import it first or the apply fails:

```bash
terraform import 'module.default.aws_cloudwatch_log_group.default[0]' /aws/lambda/<name>
```
