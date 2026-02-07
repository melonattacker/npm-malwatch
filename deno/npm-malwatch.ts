#!/usr/bin/env -S deno run

import { PRELOAD_CJS } from "./preload_cjs.ts";
import { formatPreflightText, runPreflightInstall, scanNodeModulesForScripts, ensureIgnoreScripts } from "./preflight.ts";
import { formatSummaryText, summarizeJsonl } from "./summary.ts";
import { dirname, join, resolve } from "./path.ts";

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

function usage(exitCode = 0): never {
  const msg =
    "Usage:\n" +
    "  deno run -A deno/npm-malwatch.ts [options] -- <command...>\n" +
    "  deno run -A deno/npm-malwatch.ts preflight [options] -- <pm install...>\n\n" +
    "Options:\n" +
    "  --log-file <path>\n" +
    "  --json-summary\n" +
    "  --include-pm\n" +
    "  --no-summary\n" +
    "  --hardening <detect|off>\n\n" +
    "Preflight options:\n" +
    "  --format <text|json>\n" +
    "  --output <path>\n" +
    "  --max-packages <n>\n" +
    "  --script-keys <csv>\n";
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
  subcommand: null | "preflight";
  global: GlobalOpts;
  preflight: PreflightOpts;
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

  const subcommand = argv[0] === "preflight" ? "preflight" : null;
  const sepIndex = argv.indexOf("--");
  const optPart = sepIndex >= 0 ? argv.slice(0, sepIndex) : argv;
  const cmd = sepIndex >= 0 ? argv.slice(sepIndex + 1) : [];

  for (let i = 0; i < optPart.length; i++) {
    const a = optPart[i];
    if (a === "preflight") continue;
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
    }
  }

  return { subcommand, global, preflight, cmd };
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

if (import.meta.main) {
  const argv = Deno.args;
  const parsed = parseFlags(argv);

  if (parsed.subcommand === "preflight") {
    const code = await runPreflight(parsed.preflight, parsed.cmd);
    Deno.exit(code);
  }

  const code = await runObserved(parsed.global, parsed.cmd);
  Deno.exit(code);
}
