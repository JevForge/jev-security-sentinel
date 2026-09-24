# Changelog

## [Unreleased]

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
