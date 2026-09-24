# Security policy

Report vulnerabilities privately to the JevForge maintainers. Do not open a public issue that includes secrets, raw scanner matches, or customer findings.

## What this Action does

JEV Security Sentinel reads security findings and asks Jev for a gate decision: `PASS`, `WARN`, `BLOCK`, or `REVIEW`. A deterministic policy then keeps every finding visible and refuses any Jev choice that is weaker than the configured floor.

The Action does not exploit vulnerabilities, rewrite code, or run shell commands from model output.

## Data sent to Jev

- Environment, component, and gate scope
- Counts by severity
- A bounded sample of finding ids, rules, paths, titles, CVEs, and gate effects

Secret matches, tokens, and raw secret-scanning values are dropped before the sample is built. Titles and messages pass through redaction. Provider credentials are sent only to the selected Jev endpoint.

## Credentials

Set provider and scanner secrets in the environment, never as Action inputs:

- `AI_GATEWAY_API_KEY` for `vercel-ai-gateway`
- `TYPESAFE_API_KEY` for `typesafe-native`
- `JEV_CUSTOM_API_KEY` for `custom-compatible`
- `SNYK_TOKEN`, `VERACODE_API_ID`, `VERACODE_API_KEY`, `SEMGREP_APP_TOKEN` only when those fetches are enabled

There is no silent fallback between Jev providers. Custom endpoints must be HTTPS.
