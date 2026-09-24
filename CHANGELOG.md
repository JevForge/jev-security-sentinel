# Changelog

## [Unreleased]

### Changed

* Expanded public README, examples, issue/PR templates, and contributor docs for Marketplace readiness.
* Prefixed user-facing Action logs and failures with `[JEV Security Sentinel]`.

## [0.1.0] - 2026-09-24

### Added

* Initial JEV Security Sentinel gate for normalized findings, SARIF, Semgrep, Trivy, Snyk, Veracode, and GitHub Advanced Security.
* Configurable Jev providers: `vercel-ai-gateway`, `typesafe-native`, and `custom-compatible`.
* Deterministic floor that can only make PASS, WARN, BLOCK, or REVIEW stricter, while preserving every finding.
