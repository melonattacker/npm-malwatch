# npm-malwatch

`npm-malwatch` is a wrapper CLI that helps you **understand what happens during `npm install` / `pnpm install`**.

It focuses on the most security-relevant surfaces of install-time scripts:

- **File writes** (dropping payloads, modifying configs, patching binaries)
- **Process execution** (spawning shell/curl/node, running build toolchains)
- **Network/DNS** (fetching second-stage payloads, beaconing)

`npm-malwatch` does **not** decide “malicious or not”. It only records and summarizes activity so you can review it.

## Why this is useful

Modern supply-chain attacks often hide in:

- lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`)
- binaries downloaded at install time
- “small” transitive dependencies that run scripts or spawn processes

`npm-malwatch` makes this visible in a repeatable way:

- **Observed mode**: record actual API calls that happened while you ran a command
- **Preflight**: list install scripts that *would* run (without running them)
- **Sandbox**: run install/rebuild in Docker to reduce blast radius (optional)

## Quick start

```bash
# Observed (default): record Node API usage while running a command
deno run -A deno/npm-malwatch.ts -- npm install
deno run -A deno/npm-malwatch.ts -- pnpm install
deno run -A deno/npm-malwatch.ts -- node your-script.js

# Preflight: install with --ignore-scripts, then list lifecycle scripts found in node_modules
deno run -A deno/npm-malwatch.ts preflight -- pnpm install

# Sandbox (Docker): run install/rebuild in an isolated container (observed by default)
deno run -A deno/npm-malwatch.ts sandbox -- pnpm install
deno run -A deno/npm-malwatch.ts sandbox -- pnpm rebuild
```

## Modes (what each subcommand actually does)

### 1) Observed mode (default): `npm-malwatch -- <command...>`

Observed mode runs your command while injecting a Node “preload hook” via:

- `NODE_OPTIONS=--require <generated preload.cjs>`

The preload script wraps selected Node standard library APIs and appends events to a JSONL file.

What you get:

- a JSONL log (`*.jsonl`) of the observed API calls
- a terminal summary table (by package)
- a summary CSV file (same info as the summary table)
- a **Details (top 10)** section for suspicious categories (`fs_w/proc/dns/net`)

### 2) Preflight: `npm-malwatch preflight -- <pm install...>`

Preflight is for “don’t execute scripts yet”.

What it does:

1. Detects “install-like” commands and automatically appends `--ignore-scripts` (if not already present)
2. Runs the install (so packages are fetched/unpacked, but lifecycle scripts do **not** run)
3. Scans `node_modules/**/package.json` and lists script definitions:
   - `preinstall`, `install`, `postinstall`, `prepare` (configurable via `--script-keys`)

What you get:

- a readable table on stdout (package / key / command / path)
- a JSON report (`preflight-*.json`)
- a CSV listing next to it (`preflight-*.csv`)

### 3) Sandbox (Docker): `npm-malwatch sandbox -- <pm ...>`

Sandbox runs your command inside a Docker container with a “safe-ish” profile and tries to keep your host clean:

- project directory mounted read-only (`/src:ro`)
- work directory in a Docker volume (`/work`)
- caches in a Docker volume (`/cache`)
- by default: **ephemeral volumes** (deleted after each run)
- by default: **observed mode is enabled** inside the container

This is helpful when you want to reduce the impact of “what if a script is actually malicious”.

## Requirements

- Deno (to run the CLI)
- Node.js (observed mode injects a Node preload script)
- Docker (only for `sandbox`)

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

### Where files are written

- Observed mode (default):
  - JSONL: `.npm-malwatch/<timestamp>-<pid>.jsonl`
  - CSV:  `.npm-malwatch/<timestamp>-<pid>.summary.csv`
- Sandbox mode (default):
  - JSONL: `.npm-malwatch/sandbox-<timestamp>-<pid>/events.jsonl`
  - CSV:  `.npm-malwatch/sandbox-<timestamp>-<pid>/summary.csv`
- Preflight:
  - JSON: `.npm-malwatch/preflight-<timestamp>-<pid>.json`
  - CSV:  `.npm-malwatch/preflight-<timestamp>-<pid>.csv`

The CLI summary also includes a **Details (top 10)** section for suspicious categories:

- `fs_w`: top file write paths (from `args.path`)
- `proc`: top spawned commands (from `args.file/args.argv` or `args.command`)
- `dns`: top DNS lookup hosts (from `args.host`)
- `net`: top network hosts (from `args.host/args.hostname` or best-effort `args.href`)

Each detail row includes a best-effort `Packages` column like `pacote(12), npm-registry-fetch(3)`.

## Demo

### Demo 1: normal `npm install` (real packages)

```bash
deno run -A deno/npm-malwatch.ts -- npm --prefix ./demos/demo1 install
```

### Demo 2: “malicious-like” transitive dependency (local)

`demos/demo2` contains a local transitive dependency chain:

- `demo2` (project)
  - `demo2-victim` (direct dependency)
    - `demo2-evil` (transitive dependency with `postinstall`)

`demo2-evil`’s `postinstall` script is intentionally “suspicious-looking” but safe:
it only touches local files and `localhost` (fs_w/proc/dns/net), so you can see how
`npm-malwatch` highlights these patterns.

```bash
# Preflight: list lifecycle scripts without executing them
deno run -A deno/npm-malwatch.ts preflight -- npm --prefix ./demos/demo2 install

# Observed: actually run scripts and see Details (top 10)
deno run -A deno/npm-malwatch.ts -- npm --prefix ./demos/demo2 install
```

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

### About `Root` (direct dependency)

The `Root` column is a best-effort mapping from each package to the **direct dependencies in your project’s `package.json`**
(e.g. `axios`, `bcrypt`, `eslint`). If multiple roots can reach the same package, it shows `a|b|c`.

Implementation detail:

- We build a dependency graph from package.json files found in `node_modules` and do a BFS from direct dependencies.
- This is best-effort; you may see `-` when a package cannot be mapped (e.g. package-manager internals, incomplete graph, missing metadata).

## Options

```bash
deno run -A deno/npm-malwatch.ts --log-file /tmp/malwatch.jsonl -- pnpm install
deno run -A deno/npm-malwatch.ts --json-summary -- node script.js
deno run -A deno/npm-malwatch.ts --include-pm -- npm install
deno run -A deno/npm-malwatch.ts --no-summary -- pnpm install
deno run -A deno/npm-malwatch.ts --hardening detect -- pnpm install
deno run -A deno/npm-malwatch.ts --summary-csv /tmp/summary.csv -- npm install

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

3) If you decide to execute scripts, run an observed rebuild (or install) to record behavior:

```bash
deno run -A deno/npm-malwatch.ts -- pnpm rebuild
```

4) If you want to reduce blast radius, run in Docker:

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
