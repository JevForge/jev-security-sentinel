# Feature delivery plan

Each item ships as its own branch, PR, merge to `main`, and `workflow_dispatch` release via `JevForge/jev-release-forge`.

| # | Branch | Version | Scope |
| --- | --- | --- | --- |
| 1 | `feat/baseline-new-findings` | `0.2.0` | Baseline / new-findings-only gate mode |
| 2 | `feat/multi-report-paths` | `0.3.0` | Multi-path + glob report inputs |
| 3 | `feat/check-run-idempotent-comment` | `0.4.0` | Check Run + idempotent PR comment |
| 4 | `feat/allowlist-expiry` | `0.5.0` | Allowlist expiry, owner, reason |
| 5 | `feat/jev-core-boundary` | `0.6.0` | Extractable Jev client boundary (prep for `@jevforge/core`) |
| 6 | `feat/epss-kev-enrichment` | `0.7.0` | Optional EPSS / CISA KEV enrichment |
| 7 | `feat/policy-packs` | `0.8.0` | Policy packs: strict-prod, startup, compliance |
| 8 | `feat/top-findings-output` | `0.9.0` | `top_findings` output |
| 9 | `feat/sarif-artifact-report` | `0.10.0` | SARIF export + markdown/JSON artifact report |
| 10 | `feat/sca-lockfile-scope` | `0.11.0` | SCA in-change via lockfile/package path hints |
| 11 | `feat/jev-sample-coverage` | `0.12.0` | Category coverage in Jev sample |
| 12 | `feat/reviewer-request` | `0.13.0` | Optional security team / CODEOWNERS review request |
| 13 | `feat/extra-parsers` | `0.14.0` | OSV, Grype, Checkov parsers |
| 14 | `feat/e2e-fixture-workflow` | `0.15.0` | E2E fixture workflow + structured log option |

Release command after each merge:

```bash
gh workflow run release.yml --ref main -f version=X.Y.Z -f move_major_tag=true
```
