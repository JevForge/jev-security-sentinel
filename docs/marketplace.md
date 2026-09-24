# Marketplace readiness

## Short description (≤125 characters)

```text
Turn scanner findings into a CI gate. Jev proposes PASS, WARN, BLOCK, or REVIEW; policy never hides findings.
```

## Listing fields

| Field | Value |
| --- | --- |
| Name | JEV Security Sentinel |
| Primary category | Security |
| Secondary category | Continuous integration |
| Branding | `shield` / `red` in `action.yml` |
| Pricing | Free (MIT) |

## Publish checklist

1. Public repository with root `action.yml` — done.
2. GitHub Release with a semver tag (`v0.1.1` or later) — use the Release workflow.
3. Accept the GitHub Marketplace Developer Agreement for the JevForge org (one-time).
4. Edit the latest release → check **Publish this Action to the GitHub Marketplace** → choose categories → update release (requires 2FA).

Trigger a release from Actions → Release → Run workflow with version `X.Y.Z` (same flow as `jev-model-navigator`).
