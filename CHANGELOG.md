# Changelog

## [Unreleased]

## [0.6.0] - 2026-09-24

### Changed

* Extracted a stable Jev client boundary under `src/jev/core` (prep for a future `@jevforge/core` package). Compatibility shims remain at the previous import paths.

## [0.5.0] - 2026-09-24

### Added

* Auditable allowlist `entries` with required `owner`, `reason`, and `expires_at` (YYYY-MM-DD).
* Expired entries leave findings in-scope (`ALLOWLIST_EXPIRED`); legacy array allowlists emit `ALLOWLIST_UNAUDITED`.

## [0.4.0] - 2026-09-24

### Added

* Optional Checks API run (`create_check_run`, default `true`) with decision summary and top findings.
* Idempotent PR/issue comments: re-runs update the existing `<!-- jev-security-sentinel -->` comment.

## [0.3.0] - 2026-09-24

### Added

* Report path inputs (`findings_path`, `sarif_path`, `semgrep_path`, `trivy_path`, `snyk_path`, `veracode_path`) accept comma/newline lists and workspace globs.

### Fixed

* Disabled esbuild sourcemaps so Linux release `verify-dist` matches committed `dist`.

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
