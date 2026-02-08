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
deno run -A deno/npm-malwatch.ts preflight -- npm --prefix ./demos/demo install

# sandbox (Docker isolation)
deno run -A deno/npm-malwatch.ts sandbox -- pnpm install
deno run -A deno/npm-malwatch.ts sandbox -- pnpm rebuild
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
- Summary CSV file (default: next to the JSONL log, `*.summary.csv`)
  - Columns: `root,package,total,fs_read,fs_write,proc,dns,net`

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

4) If you want to reduce blast radius, run installs in Docker:

```bash
deno run -A deno/npm-malwatch.ts sandbox -- pnpm install
```

## Notes on evasion resistance (important)

`npm-malwatch` injects a preload script via `NODE_OPTIONS=--require ...` so it runs very early in Node processes.

## Attribution notes

Package attribution (`pkg`) is best-effort:

- Primary: CommonJS module loader tracking (`Module._load`) + `AsyncLocalStorage` to propagate “current package” across async boundaries.
- Fallback: stack parsing for `.../node_modules/<pkg>/...` patterns.
- If attribution fails, `pkg` is set to `<unknown>` (it is still included in default output).

However, **100% reliable hooking is not realistic** in pure JavaScript:

- Non-Node execution (shell scripts calling `curl`, `bash`, native binaries) is out-of-scope for JS hooks.
- Native addons / direct syscalls can bypass JS-level APIs.
- A process can intentionally avoid Node entirely, or spawn processes that do not inherit `NODE_OPTIONS`.

## Sandbox notes (Docker)

The `sandbox` subcommand runs npm/pnpm in a Docker container with a “safe-ish” profile (read-only rootfs, dropped caps, no-new-privileges, tmpfs home/tmp, resource limits).

Important:
- By default, sandbox uses **ephemeral Docker volumes** for `/work` and `/cache` and deletes them after each run.
- By default, sandbox also enables **observed mode** and writes JSONL + prints a summary (disable with `--no-observe`).
- Docker is **not a perfect security boundary** (kernel vulnerabilities and misconfiguration can still lead to escapes).
- Network is allowed by default so the package manager can fetch from registries (future work: `--network none`, proxy/allowlist).

## Development

```bash
deno test -A
```

### "tamper" events

With `--hardening detect`, npm-malwatch tries to detect if key hook functions were replaced (unhooked) at runtime and logs a `tamper` event. It does **not** block execution.
