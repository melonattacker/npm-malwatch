# AGENTS.md

This repository contains `npm-malwatch`, a CLI tool that visualizes Node.js API usage during install-time execution (npm/pnpm lifecycle scripts, etc.).

## Project constraints

- **Target**: macOS/Linux, Node.js **>= 18**.
- **Offline-friendly**: This repo is intended to work in restricted environments.
  - Do **not** add new runtime dependencies unless explicitly requested.
  - Runnable outputs are committed under `dist/`.
- **No detection logic** (v0): only record + summarize usage.

## Source of truth

- `dist/*.cjs` is what actually runs and what tests import.
- `src/*.ts` exists for maintainability and documentation.

When changing behavior, **update both**:

1. Edit the TypeScript sources in `src/`.
2. Mirror the same logic into the corresponding `dist/*.cjs` files.

(`npm run build` only verifies `dist/` exists; it does not transpile.)

## How to run

- Run directly:
  - `node dist/cli.cjs -- pnpm install`
  - `node dist/cli.cjs -- npm install`
  - `node dist/cli.cjs -- node -e "require('node:fs').writeFileSync('x','1')"`

## Tests

- `npm test`
  - Uses Node’s built-in test runner (`node --test`).
  - Integration tests execute `dist/cli.cjs` and `dist/preload.cjs`.

## Logging/event conventions

- JSONL: one event per line.
- Keep event payloads bounded:
  - Truncate long strings.
  - Redact likely secrets (tokens/passwords/cookies).
- Avoid recursion in logging:
  - Use a raw `fs` fd and `writeSync` for log append.

## Implementation notes

- **Preload** should remain robust and low-risk:
  - Prefer wrapping functions without freezing/breaking built-ins.
  - Tamper handling is **detect-only** (log a `tamper` event; do not block).
- Attribution is best-effort:
  - Prefer stack-based inference (`node_modules/<pkg>` patterns).
  - Fall back to environment (`npm_package_name`, `INIT_CWD`) and then project basename.

