# Changelog

## [Unreleased]

## [0.3.0] - 2026-09-24

### Added

* Report path inputs (`findings_path`, `sarif_path`, `semgrep_path`, `trivy_path`, `snyk_path`, `veracode_path`) accept comma/newline lists and workspace globs.

## [0.2.0] - 2026-09-24

### Added

* `gate_mode: new_only` with `baseline_path` so only findings absent from a baseline fingerprint set raise the policy floor.
* Baseline matches stay visible as `gate_effect: baseline` with reason codes `BASELINE_MATCHED` and `NEW_FINDINGS_ONLY`.

## [0.1.1] - 2026-09-24

### Changed

* Aligned the Release workflow with JEV Model Navigator (publish from `workflow_dispatch` because `GITHUB_TOKEN` tag pushes do not re-trigger workflows).
* Expanded public README, examples, and GitHub templates for Marketplace readiness.
* Prefixed user-facing Action logs and failures with `[JEV Security Sentinel]`.

## [0.1.0] - 2026-09-24

### Added

* Initial JEV Security Sentinel gate for normalized findings, SARIF, Semgrep, Trivy, Snyk, Veracode, and GitHub Advanced Security.
* Configurable Jev providers: `vercel-ai-gateway`, `typesafe-native`, and `custom-compatible`.
* Deterministic floor that can only make PASS, WARN, BLOCK, or REVIEW stricter, while preserving every finding.
