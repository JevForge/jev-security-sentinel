# Jev client boundary

`src/jev/core` is the extractable client surface for JEV Security Sentinel.

## What belongs here

* `JevProvider` / `JevCallResult` / evaluation state types
* `createJevProvider` factory (no silent provider fallback)
* Evaluation response interpretation (`interpretEvaluation`)
* Question + state builders shared by every adapter

## What stays outside

Provider adapters (`vercel-ai-gateway`, `typesafe-native`, `custom-compatible`) remain Action-local implementations. Gate policy, parsers, and GitHub executors never import adapters directly.

## Future `@jevforge/core`

When a shared package ships, this folder is the intended lift target for Navigator, Sentinel, and other JEV Actions. Until then, import from `src/jev/core` (or the compatibility shims under `src/jev/*.ts`).
