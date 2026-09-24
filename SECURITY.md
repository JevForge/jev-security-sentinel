# Security policy

## Reporting a vulnerability

Do **not** open a public issue that includes secrets, tokens, raw scanner secret matches, or customer findings.

Prefer GitHub private vulnerability reporting for this repository when available (**Security → Advisories / Report a vulnerability**). Otherwise contact the JevForge organization maintainers through a private channel.

## Scope

JEV Security Sentinel reads security findings and asks Jev for a gate decision (`PASS`, `WARN`, `BLOCK`, `REVIEW`). A deterministic policy keeps every finding visible and refuses any Jev choice weaker than the configured floor.

The Action does not exploit vulnerabilities, rewrite application code, or run shell commands from model output.

## Data handling

Sent to Jev (selected provider only):

* Environment, component, gate scope, policy floor, severity counts
* A bounded, redacted sample of finding metadata

Not sent:

* Provider and scanner API keys (used only for auth to the selected endpoint)
* Raw secret-scanning match values
* Arbitrary free-form instructions as executable commands

Paths must remain inside `GITHUB_WORKSPACE`. Custom Jev endpoints must be HTTPS. There is no silent fallback between Jev providers.
