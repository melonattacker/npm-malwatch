# npm-malwatch

`npm-malwatch` is a wrapper CLI that **visualizes** potentially dangerous Node.js API usage during package installation.

It does **not** implement any detection/allowlist logic yet — it only records and summarizes API calls.

## Quick start

```bash
npm run build

npm-malwatch -- npm install
npm-malwatch -- pnpm install
npm-malwatch -- node your-script.js

# preflight (scripts are NOT executed)
npm-malwatch preflight -- pnpm install
```

## What it records

- File I/O: `fs` (sync/async + selected `fs.promises`)
- Command execution: `child_process` (`spawn/exec/execFile/fork` + sync variants)
- Network: `net`, `http`, `https`
- DNS: `dns`

Each call is appended as one JSON object per line (JSONL).

## Output

- JSONL log file (default: `.npm-malwatch/<timestamp>-<pid>.jsonl`)
- End-of-run summary (by package)

### JSONL event fields

- `ts`: epoch millis
- `session`: session id
- `pid`, `ppid`
- `pkg`: inferred package name (or `<unknown>` / `<pm:npm>` / `<pm:pnpm>`)
- `op`: e.g. `fs.writeFileSync`, `child_process.spawn`, `dns.lookup`, `http.request`
- `category`: `fs` | `proc` | `net` | `dns`
- `args`: summarized arguments (truncated)
- `result`: `ok` | `error`
- `error`: `{ name, message }` when error
- `stack`: shortened stack (optional)

## Options

```bash
npm-malwatch --log-file /tmp/malwatch.jsonl -- pnpm install
npm-malwatch --json-summary -- node script.js
npm-malwatch --include-pm -- npm install
npm-malwatch --no-summary -- pnpm install
npm-malwatch --hardening detect -- pnpm install

# preflight options
npm-malwatch preflight --format text --output .npm-malwatch/preflight.json -- pnpm install
npm-malwatch preflight --format json -- pnpm install
```

## Recommended workflow

1) **Preflight** (no scripts executed):

```bash
npm-malwatch preflight -- pnpm install
```

2) Review the report (what would run).

3) If you decide to execute scripts, run an observed rebuild:

```bash
npm-malwatch -- pnpm rebuild
```

## Notes on evasion resistance (important)

`npm-malwatch` injects a preload script via `NODE_OPTIONS=--require ...` so it runs very early in Node processes.

However, **100% reliable hooking is not realistic** in pure JavaScript:

- Non-Node execution (shell scripts calling `curl`, `bash`, native binaries) is out-of-scope for JS hooks.
- Native addons / direct syscalls can bypass JS-level APIs.
- A process can intentionally avoid Node entirely, or spawn processes that do not inherit `NODE_OPTIONS`.

## Development

This repo is designed to work in restricted/offline environments by committing runnable `dist/*.cjs` outputs.

```bash
npm test
```

### "tamper" events

With `--hardening detect`, npm-malwatch tries to detect if key hook functions were replaced (unhooked) at runtime and logs a `tamper` event. It does **not** block execution.
