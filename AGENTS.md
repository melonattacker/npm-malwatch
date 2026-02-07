# AGENTS.md

This repository contains `npm-malwatch`, a CLI tool that visualizes Node.js API usage during install-time execution (npm/pnpm lifecycle scripts, etc.).

## Project constraints

- **Target**: macOS/Linux.
  - **Deno** runs the CLI.
  - **Node.js >= 18** is required for the observed mode (preload hooks).
- **Offline-friendly**: This repo is intended to work in restricted environments.
  - Do **not** add new runtime dependencies unless explicitly requested.
  - Avoid remote URL imports in Deno modules.
- **No detection logic** (v0): only record + summarize usage.

## Source of truth

- `deno/*.ts` is the runnable implementation (CLI + preflight + summary).
- Node preload code is generated **at runtime** as a temporary `.cjs` file from `deno/preload_cjs.ts`.
- `src/*.ts` may exist as reference/legacy; keep behavior changes in `deno/` in sync with any remaining Node code if needed.

## How to run

- Observed mode (hooks via Node preload):
  - `deno run -A deno/npm-malwatch.ts -- pnpm install`
  - `deno run -A deno/npm-malwatch.ts -- npm install`
- Preflight (scripts not executed):
  - `deno run -A deno/npm-malwatch.ts preflight -- pnpm install`

## Tests

- `deno test -A`

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
