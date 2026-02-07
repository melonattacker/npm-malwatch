# npm-malwatch

`npm-malwatch` is a wrapper CLI that **visualizes** potentially dangerous Node.js API usage during package installation.

## Quick start

```bash
# observed (hooks via Node preload)
deno run -A deno/npm-malwatch.ts -- npm install
deno run -A deno/npm-malwatch.ts -- pnpm install
deno run -A deno/npm-malwatch.ts -- node your-script.js

# preflight (scripts are NOT executed)
deno run -A deno/npm-malwatch.ts preflight -- pnpm install
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
deno run -A deno/npm-malwatch.ts --log-file /tmp/malwatch.jsonl -- pnpm install
deno run -A deno/npm-malwatch.ts --json-summary -- node script.js
deno run -A deno/npm-malwatch.ts --include-pm -- npm install
deno run -A deno/npm-malwatch.ts --no-summary -- pnpm install
deno run -A deno/npm-malwatch.ts --hardening detect -- pnpm install

# preflight options
deno run -A deno/npm-malwatch.ts preflight --format text --output .npm-malwatch/preflight.json -- pnpm install
deno run -A deno/npm-malwatch.ts preflight --format json -- pnpm install
```

## Recommended workflow

1) **Preflight** (no scripts executed):

```bash
deno run -A deno/npm-malwatch.ts preflight -- pnpm install
```

2) Review the report (what would run).

3) If you decide to execute scripts, run an observed rebuild:

```bash
deno run -A deno/npm-malwatch.ts -- pnpm rebuild
```

## Notes on evasion resistance (important)

`npm-malwatch` injects a preload script via `NODE_OPTIONS=--require ...` so it runs very early in Node processes.

However, **100% reliable hooking is not realistic** in pure JavaScript:

- Non-Node execution (shell scripts calling `curl`, `bash`, native binaries) is out-of-scope for JS hooks.
- Native addons / direct syscalls can bypass JS-level APIs.
- A process can intentionally avoid Node entirely, or spawn processes that do not inherit `NODE_OPTIONS`.

## Development

```bash
deno test -A
```

### "tamper" events

With `--hardening detect`, npm-malwatch tries to detect if key hook functions were replaced (unhooked) at runtime and logs a `tamper` event. It does **not** block execution.
