# Changelog

## 0.1.0

- Initial JEV Security Sentinel gate for normalized findings, SARIF, Semgrep, Trivy, Snyk, Veracode, and GitHub Advanced Security.
- Configurable Jev providers: `vercel-ai-gateway`, `typesafe-native`, and `custom-compatible`.
- Deterministic floor that can only make PASS, WARN, BLOCK, or REVIEW stricter, while preserving every finding.
