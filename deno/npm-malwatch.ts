#!/usr/bin/env -S deno run

import { PRELOAD_CJS } from "./preload_cjs.ts";
import { formatPreflightText, runPreflightInstall, scanNodeModulesForScripts, ensureIgnoreScripts } from "./preflight.ts";
import { formatSummaryText, summarizeJsonl } from "./summary.ts";
import { dirname, join, resolve } from "./path.ts";
import {
  buildSandboxDockerRunArgs,
  defaultRunDir,
  fnv1aHex,
  type SandboxOptions,
  type SandboxObservedEnv,
} from "./sandbox.ts";

type GlobalOpts = {
  logFile?: string;
  jsonSummary: boolean;
  includePm: boolean;
  summary: boolean;
  hardening: "detect" | "off";
};

type PreflightOpts = {
  format: "text" | "json";
  output?: string;
  includePm: boolean;
  maxPackages: number;
  scriptKeys: string[];
};

type SandboxOpts = SandboxOptions;

function usage(exitCode = 0): never {
  const msg =
    "npm-malwatch (Deno CLI)\n" +
    "\n" +
    "Two modes:\n" +
    "  1) Observed mode (default): run a command while injecting a Node preload hook.\n" +
    "     - Records fs/child_process/dns/net/http(s) usage to JSONL.\n" +
    "     - Prints a package-based summary at the end.\n" +
    "  2) Preflight: run install with --ignore-scripts, then list lifecycle scripts found in node_modules.\n" +
    "     - Does NOT execute preinstall/install/postinstall/prepare.\n" +
    "  3) Sandbox (Docker): run npm/pnpm inside an isolated container (optional observe).\n" +
    "     - Keeps your host project directory clean (node_modules goes to a Docker volume).\n" +
    "\n" +
    "Usage:\n" +
    "  deno run -A deno/npm-malwatch.ts [options] -- <command...>\n" +
    "  deno run -A deno/npm-malwatch.ts preflight [options] -- <pm install...>\n" +
    "  deno run -A deno/npm-malwatch.ts sandbox [options] -- <pm install...>\n" +
    "\n" +
    "Examples:\n" +
    "  # Observed: hook npm/pnpm lifecycle script execution\n" +
    "  deno run -A deno/npm-malwatch.ts -- pnpm rebuild\n" +
    "  deno run -A deno/npm-malwatch.ts -- npm install\n" +
    "\n" +
    "  # Preflight: install dependencies without running scripts, then list them\n" +
    "  deno run -A deno/npm-malwatch.ts preflight -- pnpm install\n" +
    "\n" +
    "  # Sandbox (Docker): run install in an isolated container\n" +
    "  deno run -A deno/npm-malwatch.ts sandbox -- pnpm install\n" +
    "\n" +
    "  # Sandbox (Docker) logs JSONL by default; disable with --no-observe\n" +
    "  deno run -A deno/npm-malwatch.ts sandbox -- pnpm rebuild\n" +
    "\n" +
    "Observed mode options:\n" +
    "  --log-file <path>\n" +
    "      Write JSONL events to this file.\n" +
    "      Default: .npm-malwatch/<timestamp>-<pid>.jsonl\n" +
    "\n" +
    "  --json-summary\n" +
    "      Print the end-of-run summary as JSON (stdout).\n" +
    "\n" +
    "  --include-pm\n" +
    "      Include events/scripts attributed to the package manager itself (npm/pnpm).\n" +
    "      Default: excluded (noise reduction).\n" +
    "\n" +
    "  --no-summary\n" +
    "      Do not print the end-of-run summary (log only).\n" +
    "\n" +
    "  --hardening <detect|off>\n" +
    "      detect: log a \"tamper\" event if hooks look replaced at runtime.\n" +
    "      off:    disable tamper checks.\n" +
    "      Default: detect\n" +
    "\n" +
    "Preflight options:\n" +
    "  --format <text|json>\n" +
    "      text: human-readable list (stdout).\n" +
    "      json:  machine-readable report (stdout).\n" +
    "      Default: text\n" +
    "\n" +
    "  --output <path>\n" +
    "      Always write the JSON report to this path.\n" +
    "      Default: .npm-malwatch/preflight-<timestamp>-<pid>.json\n" +
    "\n" +
    "  --max-packages <n>\n" +
    "      Maximum number of package.json files to scan (DoS protection).\n" +
    "      Default: 20000\n" +
    "\n" +
    "  --script-keys <csv>\n" +
    "      Comma-separated script keys to extract.\n" +
    "      Default: preinstall,install,postinstall,prepare\n" +
    "\n" +
    "Sandbox (Docker) options:\n" +
    "  --image <name>\n" +
    "      Docker image to use.\n" +
    "      Default: node:22-bookworm-slim@sha256:5373f1906319b3a1f291da5d102f4ce5c77ccbe29eb637f072b6c7b70443fc36\n" +
    "\n" +
    "  --no-observe\n" +
    "      Do not inject the Node preload hook in the container.\n" +
    "      When set, sandbox runs install without JSONL/summary output.\n" +
    "      Default: observe enabled\n" +
    "\n" +
    "  --persist-volumes\n" +
    "      Keep Docker volumes after the run (speed up subsequent installs).\n" +
    "      Default: ephemeral (deleted after each run)\n" +
    "\n" +
    "  --work-volume <name>\n" +
    "      Docker volume used as /work (project copy + node_modules).\n" +
    "      Note: specifying this implies --persist-volumes.\n" +
    "\n" +
    "  --cache-volume <name>\n" +
    "      Docker volume used as /cache (npm/pnpm/corepack caches).\n" +
    "      Note: specifying this implies --persist-volumes.\n" +
    "\n" +
    "  --network <mode>\n" +
    "      Docker network mode (e.g. bridge, none).\n" +
    "      Default: bridge\n" +
    "\n" +
    "  --memory <size>\n" +
    "      Docker memory limit.\n" +
    "      Default: 2g\n" +
    "\n" +
    "  --cpus <n>\n" +
    "      Docker CPU limit.\n" +
    "      Default: 2\n" +
    "\n" +
    "  --pids-limit <n>\n" +
    "      Docker PID limit.\n" +
    "      Default: 512\n" +
    "\n" +
    "Notes:\n" +
    "  - Observed mode requires Node.js (it injects a temporary preload .cjs via NODE_OPTIONS).\n" +
    "  - Preflight automatically appends --ignore-scripts only for install-like commands.\n" +
    "  - Package attribution is best-effort (CommonJS module loader + AsyncLocalStorage; stack as fallback).\n" +
    "    When attribution fails, events use pkg=<unknown> (and are still shown in package-only mode).\n" +
    "  - Sandbox uses Docker and is not a perfect security boundary.\n" +
    "  - Deno permissions: -A is easiest; minimum is --allow-run --allow-read --allow-write --allow-env.\n";
  // eslint-disable-next-line no-console
  console.error(msg);
  Deno.exit(exitCode);
}

function die(msg: string, exitCode = 2): never {
  // eslint-disable-next-line no-console
  console.error(`Error: ${msg}`);
  Deno.exit(exitCode);
}

function ensureDirForFile(filePath: string): void {
  Deno.mkdirSync(dirname(filePath), { recursive: true });
}

function defaultLogFile(): string {
  return join(Deno.cwd(), ".npm-malwatch", `${Date.now()}-${Deno.pid}.jsonl`);
}

function defaultPreflightOutput(): string {
  return join(Deno.cwd(), ".npm-malwatch", `preflight-${Date.now()}-${Deno.pid}.json`);
}

function mergeNodeOptions(existing: string | undefined, preloadPath: string): string {
  const req = `--require ${JSON.stringify(preloadPath)}`;
  const base = existing?.trim() ? existing.trim() : "";
  if (base.includes(preloadPath) && base.includes("--require")) return base;
  if (!base) return req;
  return `${base} ${req}`;
}

function parseFlags(argv: string[]): {
  subcommand: null | "preflight" | "sandbox";
  global: GlobalOpts;
  preflight: PreflightOpts;
  sandbox: SandboxOpts;
  cmd: string[];
} {
  const global: GlobalOpts = {
    logFile: undefined,
    jsonSummary: false,
    includePm: false,
    summary: true,
    hardening: "detect"
  };

  const preflight: PreflightOpts = {
    format: "text",
    output: undefined,
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ["preinstall", "install", "postinstall", "prepare"]
  };

  const runId = `${Date.now()}-${Deno.pid}`;
  const h = fnv1aHex(Deno.cwd());
  const sandbox: SandboxOpts = {
    image: "node:22-bookworm-slim@sha256:5373f1906319b3a1f291da5d102f4ce5c77ccbe29eb637f072b6c7b70443fc36",
    observe: true,
    ephemeralVolumes: true,
    workVolume: `npm-malwatch-work-${h}-${runId}`,
    cacheVolume: `npm-malwatch-cache-${h}-${runId}`,
    network: "bridge",
    memory: "2g",
    cpus: "2",
    pidsLimit: 512
  };

  const subcommand = argv[0] === "preflight" ? "preflight" : argv[0] === "sandbox" ? "sandbox" : null;
  const sepIndex = argv.indexOf("--");
  const optPart = sepIndex >= 0 ? argv.slice(0, sepIndex) : argv;
  const cmd = sepIndex >= 0 ? argv.slice(sepIndex + 1) : [];

  for (let i = 0; i < optPart.length; i++) {
    const a = optPart[i];
    if (a === "preflight") continue;
    if (a === "sandbox") continue;
    if (a === "-h" || a === "--help") usage(0);

    if (a === "--log-file") global.logFile = optPart[++i];
    else if (a === "--json-summary") global.jsonSummary = true;
    else if (a === "--include-pm") {
      global.includePm = true;
      preflight.includePm = true;
    } else if (a === "--no-summary") global.summary = false;
    else if (a === "--hardening") {
      const v = optPart[++i] ?? "detect";
      global.hardening = v === "off" ? "off" : "detect";
    } else if (a === "--format") {
      const v = optPart[++i] ?? "text";
      preflight.format = v === "json" ? "json" : "text";
    } else if (a === "--output") {
      preflight.output = optPart[++i];
    } else if (a === "--max-packages") {
      const n = Number.parseInt(optPart[++i] ?? "20000", 10);
      preflight.maxPackages = Number.isFinite(n) && n > 0 ? n : 20000;
    } else if (a === "--script-keys") {
      const csv = optPart[++i] ?? "";
      preflight.scriptKeys = csv.split(",").map((s) => s.trim()).filter(Boolean);
      if (preflight.scriptKeys.length === 0) preflight.scriptKeys = ["preinstall", "install", "postinstall", "prepare"];
    } else if (a === "--image") {
      sandbox.image = optPart[++i] ?? sandbox.image;
    } else if (a === "--observe") {
      // Backward compatible flag (observe is default).
      sandbox.observe = true;
    } else if (a === "--no-observe") {
      sandbox.observe = false;
    } else if (a === "--persist-volumes") {
      sandbox.ephemeralVolumes = false;
    } else if (a === "--work-volume") {
      sandbox.workVolume = optPart[++i] ?? sandbox.workVolume;
      sandbox.ephemeralVolumes = false;
    } else if (a === "--cache-volume") {
      sandbox.cacheVolume = optPart[++i] ?? sandbox.cacheVolume;
      sandbox.ephemeralVolumes = false;
    } else if (a === "--network") {
      sandbox.network = optPart[++i] ?? sandbox.network;
    } else if (a === "--memory") {
      sandbox.memory = optPart[++i] ?? sandbox.memory;
    } else if (a === "--cpus") {
      sandbox.cpus = optPart[++i] ?? sandbox.cpus;
    } else if (a === "--pids-limit") {
      const n = Number.parseInt(optPart[++i] ?? "512", 10);
      sandbox.pidsLimit = Number.isFinite(n) && n > 0 ? n : sandbox.pidsLimit;
    }
  }

  return { subcommand, global, preflight, sandbox, cmd };
}

async function removeDockerVolumes(volumes: string[]): Promise<void> {
  const uniq = [...new Set(volumes.filter((v) => v.trim().length > 0))];
  if (uniq.length === 0) return;
  const child = new Deno.Command("docker", {
    args: ["volume", "rm", ...uniq],
    stdin: "null",
    stdout: "inherit",
    stderr: "inherit",
    env: { ...Deno.env.toObject() }
  }).spawn();
  const status = await child.status;
  if (!status.success) {
    // eslint-disable-next-line no-console
    console.error(`npm-malwatch sandbox: failed to remove volumes: ${uniq.join(", ")}`);
  }
}

async function runObserved(global: GlobalOpts, cmd: string[]): Promise<number> {
  if (!cmd.length) die("Missing command. Usage: ... -- <command...>");

  const logFile = resolve(Deno.cwd(), global.logFile ?? defaultLogFile());
  ensureDirForFile(logFile);

  const session = `${Date.now()}-${Deno.pid}`;

  const tmpDir = await Deno.makeTempDir({ prefix: "npm-malwatch-" });
  const preloadPath = join(tmpDir, "preload.cjs");
  await Deno.writeTextFile(preloadPath, PRELOAD_CJS);

  const env = {
    ...Deno.env.toObject(),
    NPM_MALWATCH_LOG: logFile,
    NPM_MALWATCH_SESSION: session,
    NPM_MALWATCH_FILTER: "package-only",
    NPM_MALWATCH_INCLUDE_PM: global.includePm ? "1" : "0",
    NPM_MALWATCH_HARDENING: global.hardening,
    NODE_OPTIONS: mergeNodeOptions(Deno.env.get("NODE_OPTIONS") ?? undefined, preloadPath)
  };

  // eslint-disable-next-line no-console
  console.error(`npm-malwatch: logging to ${logFile}`);

  const child = new Deno.Command(cmd[0]!, {
    args: cmd.slice(1),
    env,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit"
  }).spawn();
  const status = await child.status;

  if (global.summary) {
    try {
      const summary = await summarizeJsonl(logFile);
      if (global.jsonSummary) {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(summary, null, 2));
      } else {
        // eslint-disable-next-line no-console
        console.log("");
        // eslint-disable-next-line no-console
        console.log("npm-malwatch summary");
        // eslint-disable-next-line no-console
        console.log(formatSummaryText(summary));
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(`Failed to summarize log: ${String(e)}`);
    }
  }

  return status.code;
}

async function runPreflight(preflight: PreflightOpts, cmd: string[]): Promise<number> {
  if (!cmd.length) die("Missing command. Usage: ... preflight -- <command...>");

  const outputPath = resolve(Deno.cwd(), preflight.output ?? defaultPreflightOutput());
  ensureDirForFile(outputPath);

  const { pmCommand } = ensureIgnoreScripts(cmd);
  // eslint-disable-next-line no-console
  console.error(`npm-malwatch preflight: running ${pmCommand.join(" ")}`);
  const code = await runPreflightInstall(pmCommand, Deno.cwd());
  if (code !== 0) return code;

  const report = scanNodeModulesForScripts(Deno.cwd(), {
    includePm: preflight.includePm,
    maxPackages: preflight.maxPackages,
    scriptKeys: preflight.scriptKeys
  });
  report.pmCommand = pmCommand;

  await Deno.writeTextFile(outputPath, JSON.stringify(report, null, 2));

  if (preflight.format === "json") {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(report, null, 2));
  } else {
    // eslint-disable-next-line no-console
    console.log(formatPreflightText(report));
    // eslint-disable-next-line no-console
    console.log("");
    // eslint-disable-next-line no-console
    console.log(`Report written: ${outputPath}`);
  }

  return 0;
}

async function runSandbox(sandbox: SandboxOpts, global: GlobalOpts, cmd: string[]): Promise<number> {
  if (!cmd.length) die("Missing command. Usage: ... sandbox -- <command...>");

  const cwd = Deno.cwd();
  const runDir = defaultRunDir(cwd);
  Deno.mkdirSync(runDir, { recursive: true });

  const observed: SandboxObservedEnv | undefined = sandbox.observe
    ? (() => {
      const session = `${Date.now()}-${Deno.pid}`;
      const logHostPath = resolve(cwd, global.logFile ?? join(runDir, "events.jsonl"));
      const preloadHostPath = join(dirname(logHostPath), "preload.cjs");
      Deno.mkdirSync(dirname(logHostPath), { recursive: true });
      Deno.writeTextFileSync(preloadHostPath, PRELOAD_CJS);
      // eslint-disable-next-line no-console
      console.error(`npm-malwatch sandbox: run dir ${dirname(logHostPath)}`);
      // eslint-disable-next-line no-console
      console.error(`npm-malwatch sandbox: jsonl ${logHostPath}`);
      return {
        preloadHostPath,
        logHostPath,
        session,
        includePm: global.includePm,
        hardening: global.hardening
      };
    })()
    : undefined;

  if (!sandbox.observe) {
    // eslint-disable-next-line no-console
    console.error("npm-malwatch sandbox: observe is off (no JSONL/summary output).");
  } else if (sandbox.ephemeralVolumes) {
    // eslint-disable-next-line no-console
    console.error(
      `npm-malwatch sandbox: ephemeral volumes (will delete): ${sandbox.workVolume}, ${sandbox.cacheVolume}`,
    );
  } else {
    // eslint-disable-next-line no-console
    console.error(`npm-malwatch sandbox: persistent volumes: ${sandbox.workVolume}, ${sandbox.cacheVolume}`);
  }

  const dockerArgs = buildSandboxDockerRunArgs({
    cwd,
    sandbox,
    command: cmd,
    runDirHostPath: runDir,
    observed
  });

  // eslint-disable-next-line no-console
  console.error(`npm-malwatch sandbox: docker ${dockerArgs.join(" ")}`);

  const child = new Deno.Command("docker", {
    args: dockerArgs,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
    env: { ...Deno.env.toObject() }
  }).spawn();
  const status = await child.status;

  if (sandbox.observe && observed && global.summary) {
    try {
      const summary = await summarizeJsonl(observed.logHostPath);
      if (global.jsonSummary) {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(summary, null, 2));
      } else {
        // eslint-disable-next-line no-console
        console.log("");
        // eslint-disable-next-line no-console
        console.log("npm-malwatch summary");
        // eslint-disable-next-line no-console
        console.log(formatSummaryText(summary));
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(`Failed to summarize log: ${String(e)}`);
    }
  }

  if (sandbox.ephemeralVolumes) {
    await removeDockerVolumes([sandbox.workVolume, sandbox.cacheVolume]);
  }

  return status.code;
}

if (import.meta.main) {
  const argv = Deno.args;
  const parsed = parseFlags(argv);

  if (parsed.subcommand === "preflight") {
    const code = await runPreflight(parsed.preflight, parsed.cmd);
    Deno.exit(code);
  }

  if (parsed.subcommand === "sandbox") {
    const code = await runSandbox(parsed.sandbox, parsed.global, parsed.cmd);
    Deno.exit(code);
  }

  {
    const code = await runObserved(parsed.global, parsed.cmd);
    Deno.exit(code);
  }
}
