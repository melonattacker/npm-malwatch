#!/usr/bin/env -S deno run

import { PRELOAD_CJS } from "./preload_cjs.ts";
import {
  formatPreflightCsv,
  formatPreflightText,
  runPreflightInstall,
  scanNodeModulesForScripts,
  ensureIgnoreScripts
} from "./preflight.ts";
import { formatSummaryCsv, formatSummaryText, summarizeJsonl } from "./summary.ts";
import { dirname, join, resolve } from "./path.ts";
import { computeRootByPackageFromNodeModules } from "./roots.ts";
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
  summaryCsv: boolean;
  summaryCsvFile?: string;
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
    "  --summary-csv <path>\n" +
    "      Write the package summary table as CSV.\n" +
    "      Default: enabled (auto path next to the JSONL log).\n" +
    "\n" +
    "  --no-summary-csv\n" +
    "      Disable writing the summary CSV file.\n" +
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
    "  (output)\n" +
    "      Preflight always writes:\n" +
    "        - JSON report:  --output <path> (default: .npm-malwatch/preflight-<timestamp>-<pid>.json)\n" +
    "        - CSV listing:  next to the JSON report (same name, .csv)\n" +
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
    "    The summary table also shows a best-effort direct dependency root (one level above your project).\n" +
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

function defaultPreflightCsvOutput(jsonPath: string): string {
  if (jsonPath.endsWith(".json")) return jsonPath.slice(0, -".json".length) + ".csv";
  return jsonPath + ".csv";
}

function mergeNodeOptions(existing: string | undefined, preloadPath: string): string {
  const req = `--require ${JSON.stringify(preloadPath)}`;
  const base = existing?.trim() ? existing.trim() : "";
  if (base.includes(preloadPath) && base.includes("--require")) return base;
  if (!base) return req;
  return `${base} ${req}`;
}

async function writeSummaryCsv(summary: unknown, csvPath: string): Promise<void> {
  ensureDirForFile(csvPath);
  await Deno.writeTextFile(csvPath, formatSummaryCsv(summary as any));
  // eslint-disable-next-line no-console
  console.error(`npm-malwatch: wrote summary csv to ${csvPath}`);
}

function defaultSummaryCsvPath(logFile: string): string {
  if (logFile.endsWith(".jsonl")) return logFile.slice(0, -".jsonl".length) + ".summary.csv";
  return logFile + ".summary.csv";
}

function inferProjectRootFromCommand(cwd: string, cmd: string[]): string {
  // Best-effort: support npm "--prefix" and pnpm "-C"/"--dir".
  const takeNext = (flag: string): string | null => {
    const idx = cmd.indexOf(flag);
    if (idx === -1) return null;
    const v = cmd[idx + 1];
    if (!v || v.startsWith("-")) return null;
    return v;
  };

  const prefix = takeNext("--prefix") ?? takeNext("-C") ?? takeNext("--dir");
  if (!prefix) return cwd;
  return resolve(cwd, prefix);
}

function inferNodeModulesScanRootFromCommand(cwd: string, cmd: string[]): string {
  const candidates: string[] = [];
  candidates.push(inferProjectRootFromCommand(cwd, cmd));

  for (const token of cmd) {
    if (!token || token.startsWith("-")) continue;
    const abs = resolve(cwd, token);
    try {
      const st = Deno.statSync(abs);
      if (!st.isDirectory) continue;
    } catch {
      continue;
    }
    try {
      if (!Deno.statSync(join(abs, "package.json")).isFile) continue;
    } catch {
      continue;
    }
    candidates.push(abs);
  }

  candidates.push(cwd);

  const seen = new Set<string>();
  const uniq = candidates.filter((c) => {
    if (seen.has(c)) return false;
    seen.add(c);
    return true;
  });

  for (const c of uniq) {
    try {
      if (Deno.statSync(join(c, "node_modules")).isDirectory) return c;
    } catch {
      // continue
    }
  }

  return uniq[0] ?? cwd;
}

function normalizePosixRel(p: string): string {
  // For container paths. Keep it simple.
  let out = p.replaceAll("\\", "/");
  if (out.startsWith("./")) out = out.slice(2);
  while (out.startsWith("/")) out = out.slice(1);
  return out;
}

async function computeRootsInSandbox(
  image: string,
  workVolume: string,
  projectRel: string,
  outDirHost: string,
  pkgs: string[],
): Promise<Record<string, string | null>> {
  const outPathHost = join(outDirHost, "roots.json");
  const projectRoot = projectRel ? `/work/${normalizePosixRel(projectRel)}` : "/work";

  const js = `
const fs = require("node:fs");
const path = require("node:path");

function safeReadJson(p) { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } }
function listNpmStyle(nm, out, max) {
  let entries = [];
  try { entries = fs.readdirSync(nm, { withFileTypes: true }); } catch { return; }
  entries.sort((a,b)=>a.name.localeCompare(b.name));
  for (const e of entries) {
    if (out.length >= max) break;
    if (!e.isDirectory()) continue;
    if (e.name === ".bin" || e.name === ".pnpm") continue;
    const full = path.join(nm, e.name);
    if (e.name.startsWith("@")) {
      let scoped = [];
      try { scoped = fs.readdirSync(full, { withFileTypes: true }); } catch { scoped = []; }
      scoped.sort((a,b)=>a.name.localeCompare(b.name));
      for (const se of scoped) {
        if (out.length >= max) break;
        if (!se.isDirectory()) continue;
        out.push(path.join(full, se.name, "package.json"));
      }
    } else {
      out.push(path.join(full, "package.json"));
    }
  }
}
function listPnpmStyle(nm, out, max) {
  const pnpmRoot = path.join(nm, ".pnpm");
  let store = [];
  try { store = fs.readdirSync(pnpmRoot, { withFileTypes: true }); } catch { return; }
  store.sort((a,b)=>a.name.localeCompare(b.name));
  for (const e of store) {
    if (out.length >= max) break;
    if (!e.isDirectory()) continue;
    listNpmStyle(path.join(pnpmRoot, e.name, "node_modules"), out, max);
  }
}

const projectRoot = ${JSON.stringify(projectRoot)};
const pkgJson = safeReadJson(path.join(projectRoot, "package.json")) || {};
const direct = new Set();
for (const k of ["dependencies","devDependencies","optionalDependencies","peerDependencies"]) {
  const obj = pkgJson[k];
  if (!obj || typeof obj !== "object") continue;
  for (const name of Object.keys(obj)) direct.add(name);
}

const nmRoot = path.join(projectRoot, "node_modules");
const paths = [];
listNpmStyle(nmRoot, paths, 50001);
if (paths.length < 50001) listPnpmStyle(nmRoot, paths, 50001);

function depsFrom(json) {
  const out = new Set();
  for (const k of ["dependencies","optionalDependencies","peerDependencies"]) {
    const obj = json && json[k];
    if (!obj || typeof obj !== "object") continue;
    for (const name of Object.keys(obj)) out.add(name);
  }
  return [...out];
}

const graph = new Map();
for (const p of paths.slice(0, 50000)) {
  const json = safeReadJson(p);
  if (!json) continue;
  const name = typeof json.name === "string" ? json.name : path.basename(path.dirname(p));
  const deps = depsFrom(json);
  const set = graph.get(name) || new Set();
  for (const d of deps) set.add(d);
  graph.set(name, set);
}

const targets = new Set(JSON.parse(process.env.NPM_MALWATCH_TARGET_PKGS || "[]"));
const rootsFor = new Map();
const q = [];
for (const r of [...direct]) q.push([r,r]);
const seen = new Set();
while (q.length) {
  const [pkg, root] = q.shift();
  const key = root + "\\0" + pkg;
  if (seen.has(key)) continue;
  seen.add(key);
  const set = rootsFor.get(pkg) || new Set();
  set.add(root);
  rootsFor.set(pkg, set);
  const children = graph.get(pkg);
  if (!children) continue;
  for (const c of children) q.push([c, root]);
}

const out = {};
for (const p of targets) {
  if (typeof p !== "string" || p.startsWith("<")) { out[p] = null; continue; }
  const rs = rootsFor.get(p);
  if (!rs || rs.size === 0) out[p] = null;
  else out[p] = [...rs].sort().join("|");
}
for (const r of direct) {
  if (targets.has(r) && !out[r]) out[r] = r;
}

fs.writeFileSync("/out/roots.json", JSON.stringify(out, null, 2));
`;

  const dockerArgs = [
    "run",
    "--rm",
    "-v",
    `${workVolume}:/work`,
    "-v",
    `${outDirHost}:/out`,
    "-e",
    `NPM_MALWATCH_TARGET_PKGS=${JSON.stringify(pkgs)}`,
    image,
    "node",
    "-e",
    js
  ];

  const child = new Deno.Command("docker", {
    args: dockerArgs,
    stdin: "null",
    stdout: "inherit",
    stderr: "inherit",
    env: { ...Deno.env.toObject() }
  }).spawn();
  const st = await child.status;
  if (!st.success) return {};

  try {
    const raw = await Deno.readTextFile(outPathHost);
    return JSON.parse(raw);
  } catch {
    return {};
  }
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
    summaryCsv: true,
    summaryCsvFile: undefined,
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
    else if (a === "--summary-csv") {
      global.summaryCsv = true;
      global.summaryCsvFile = optPart[++i];
      if (!global.summaryCsvFile) die("Missing value for --summary-csv <path>");
    } else if (a === "--no-summary-csv") global.summaryCsv = false;
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
      const projectRoot = inferProjectRootFromCommand(Deno.cwd(), cmd);
      summary.rootByPackage = computeRootByPackageFromNodeModules(projectRoot, Object.keys(summary.byPackage));
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

      if (global.summaryCsv) {
        const csvPath = resolve(Deno.cwd(), global.summaryCsvFile ?? defaultSummaryCsvPath(logFile));
        await writeSummaryCsv(summary, csvPath);
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
  const csvPath = defaultPreflightCsvOutput(outputPath);

  const { pmCommand } = ensureIgnoreScripts(cmd);
  // eslint-disable-next-line no-console
  console.error(`npm-malwatch preflight: running ${pmCommand.join(" ")}`);
  const code = await runPreflightInstall(pmCommand, Deno.cwd());
  if (code !== 0) return code;

  // Install may target a sub-project (e.g. `npm --prefix ./path install`).
  // Scan that project’s node_modules for lifecycle scripts.
  const projectRoot = inferNodeModulesScanRootFromCommand(Deno.cwd(), pmCommand);
  const report = scanNodeModulesForScripts(projectRoot, {
    includePm: preflight.includePm,
    maxPackages: preflight.maxPackages,
    scriptKeys: preflight.scriptKeys
  });
  report.pmCommand = pmCommand;

  await Deno.writeTextFile(outputPath, JSON.stringify(report, null, 2));
  await Deno.writeTextFile(csvPath, formatPreflightCsv(report));

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
    // eslint-disable-next-line no-console
    console.log(`CSV written: ${csvPath}`);
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
      // Try to attribute each package to a direct dependency root. In sandbox mode,
      // node_modules lives inside the Docker work volume, so we compute this via
      // an extra docker run before volumes are deleted.
      const projectRootHost = inferProjectRootFromCommand(cwd, cmd);
      summary.rootByPackage = computeRootByPackageFromNodeModules(projectRootHost, Object.keys(summary.byPackage));
      const hasAnyRoots = Object.values(summary.rootByPackage).some((v) => typeof v === "string" && v.length > 0);
      if (!hasAnyRoots) {
        const projectRel = cmd.includes("--prefix") ? (cmd[cmd.indexOf("--prefix") + 1] ?? "") : "";
        const outDirHost = dirname(observed.logHostPath);
        const roots = await computeRootsInSandbox(sandbox.image, sandbox.workVolume, projectRel, outDirHost, Object.keys(summary.byPackage));
        for (const [k, v] of Object.entries(roots)) summary.rootByPackage[k] = v;
      }
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

      if (global.summaryCsv) {
        const defaultPath = join(dirname(observed.logHostPath), "summary.csv");
        const csvPath = resolve(cwd, global.summaryCsvFile ?? defaultPath);
        await writeSummaryCsv(summary, csvPath);
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
