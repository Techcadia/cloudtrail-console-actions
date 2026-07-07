# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] — unreleased

### Changed (breaking)

- **Declarative policy engine replaces the hardcoded filter.** Filtering is now
  driven by a FilterPolicy YAML document ([schema](./policy.schema.json)); the
  v1 ruleset is embedded as a golden-tested default and can be overridden with
  `--config-file` / `CCA_POLICY_FILE` without recompiling.
- **Log format** is now slog-style (`"level":"INFO"`) instead of logrus-style
  (`"level":"info"`). The `Event` log contract (`msg == "Event"`, field names)
  and all `SLACK_*` variables are unchanged.
- **`keep` rules always emit security writes** (`DeleteTrail`, `StopLogging`,
  `PutUserPolicy`, `DeleteFlowLogs`, `UpdateTrail`) even from non-console user
  agents that v1 dropped.
- **Deduplication is configurable** (`--dedupe` / `CCA_DEDUPE`, default on) and
  flush order is deterministic.

### Added

- `--validate-only` and `--dump-default-policy` flags.
- Per-record decision tracing at `LOG_LEVEL=debug`.
- [Policy language reference](./docs/policy-language.md).

### Fixed

- Hot-path allocations reduced ~20x (per-record numeric coercion no longer
  allocates on non-numeric strings; disabled tracer no longer boxes arguments).
- Slack console deep-link parameters are now URL-encoded (assumed-role / SSO
  principals no longer break the link).
- Malformed / non-CloudTrail S3 objects are logged and skipped instead of
  failing (and endlessly retrying) the whole invocation.
- Terraform: S3 example module now plans/applies cleanly (correct module source
  paths, artifact filename, managed log group with retention, least-privilege
  IAM).

### Upgrading from v1

Redeploy the same Terraform module against the new artifact (`make zip` now
produces `dist/function_arm64.zip`). No policy migration is required — the
embedded default reproduces v1 (v0.3.2) decisions, verified against a ~350k
record parity corpus. To customize, start from `--dump-default-policy`.
