# Contributing

Thanks for helping improve JEV Security Sentinel.

## Setup

```bash
git clone https://github.com/JevForge/jev-security-sentinel.git
cd jev-security-sentinel
npm ci
```

Requires **Node.js 24+**.

## Local checks

```bash
npm test
npm run typecheck
npm run build
# or
npm run all
```

## Guidelines

1. Keep the public decision schema backward compatible. Add reason codes; do not rename existing ones.
2. Keep Jev access behind `JevProvider`. Do not execute explanation text.
3. New scanner sources must normalize into the existing finding schema and keep suppressed/allowlisted findings visible.
4. Rebuild and commit `dist/index.js` when the Action entrypoint changes (consumers do not run `npm install`).
5. Prefer small PRs with tests for schema, policy, and parser changes.

## Pull requests

Use the PR template checklist. Do not publish releases or Marketplace listings from a pull request.

## Issues

Use the bug / feature templates. Never paste API keys, tokens, or raw secret-scanning matches.
