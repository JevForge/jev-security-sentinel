# Contributing

Issues and pull requests are welcome.

1. Use Node.js 24.
2. Run `npm ci`, `npm test`, `npm run typecheck`, and `npm run build`.
3. Keep the public decision schema backward compatible. Add reason codes; do not rename existing ones.
4. Jev output must stay behind `JevProvider`. Do not execute explanation text.
5. New scanner sources should normalize into the existing finding schema and keep suppressed findings visible.
6. Commit `dist/index.js` when the Action entrypoint changes so consumers do not run `npm install`.

Do not publish a release or a Marketplace listing from a pull request.
