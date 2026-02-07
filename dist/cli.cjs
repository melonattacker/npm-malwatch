#!/usr/bin/env node
"use strict";

const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const process = require("node:process");
const { summarizeJsonl, formatSummaryText } = require("./summary.cjs");
const {
  ensureIgnoreScripts,
  runPreflightInstall,
  scanNodeModulesForScripts,
  formatPreflightText
} = require("./preflight.cjs");

function pcDim(s) {
  return `\u001b[2m${s}\u001b[22m`;
}
function pcBold(s) {
  return `\u001b[1m${s}\u001b[22m`;
}
function pcRed(s) {
  return `\u001b[31m${s}\u001b[39m`;
}
function pcYellow(s) {
  return `\u001b[33m${s}\u001b[39m`;
}

function findDistPreloadPath() {
  const guess = path.resolve(__dirname, "preload.cjs");
  if (fs.existsSync(guess)) return guess;
  const guess2 = path.resolve(process.cwd(), "dist", "preload.cjs");
  return guess2;
}

function defaultLogFile() {
  const dir = path.resolve(process.cwd(), ".npm-malwatch");
  const file = `${Date.now()}-${process.pid}.jsonl`;
  return path.join(dir, file);
}

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function mergeNodeOptions(existing, preloadPath) {
  const req = `--require ${JSON.stringify(preloadPath)}`;
  const base = existing?.trim() ? existing.trim() : "";
  if (base.includes(preloadPath) && base.includes("--require")) return base;
  if (!base) return req;
  return `${base} ${req}`;
}

function usageError(msg) {
  console.error(pcRed(`Error: ${msg}`));
  process.exit(2);
}

function parseArgs(argv) {
  const out = {
    subcommand: null,
    logFile: void 0,
    jsonSummary: false,
    includePm: false,
    summary: true,
    hardening: "detect",
    cmd: [],
    preflight: {
      format: "text",
      output: void 0,
      includePm: false,
      maxPackages: 20000,
      scriptKeys: "preinstall,install,postinstall,prepare"
    }
  };

  const args = argv.slice(2);
  if (args[0] === "preflight") {
    out.subcommand = "preflight";
  }
  const sep = args.indexOf("--");
  const optPart = sep >= 0 ? args.slice(0, sep) : args;
  out.cmd = sep >= 0 ? args.slice(sep + 1) : [];

  for (let i = 0; i < optPart.length; i++) {
    const a = optPart[i];
    if (a === "preflight") continue;
    if (a === "--log-file") {
      out.logFile = optPart[++i];
    } else if (a === "--json-summary") {
      out.jsonSummary = true;
    } else if (a === "--include-pm") {
      out.includePm = true;
      out.preflight.includePm = true;
    } else if (a === "--no-summary") {
      out.summary = false;
    } else if (a === "--hardening") {
      out.hardening = optPart[++i] || "detect";
    } else if (a === "--format") {
      out.preflight.format = optPart[++i] || "text";
    } else if (a === "--output") {
      out.preflight.output = optPart[++i];
    } else if (a === "--max-packages") {
      out.preflight.maxPackages = Number.parseInt(optPart[++i] || "20000", 10) || 20000;
    } else if (a === "--script-keys") {
      out.preflight.scriptKeys = optPart[++i] || out.preflight.scriptKeys;
    } else if (a === "-h" || a === "--help") {
      console.log(
        "Usage: npm-malwatch [options] -- <command...>\n" +
          "       npm-malwatch preflight [options] -- <pm install...>\n\n" +
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
          "  --script-keys <csv>"
      );
      process.exit(0);
    }
  }
  return out;
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.subcommand === "preflight") {
    if (!opts.cmd.length) usageError("Missing command. Usage: npm-malwatch preflight -- <command...>");

    const reportPath = path.resolve(
      process.cwd(),
      opts.preflight.output ?? path.join(".npm-malwatch", `preflight-${Date.now()}-${process.pid}.json`)
    );
    ensureDir(reportPath);

    const scriptKeys = String(opts.preflight.scriptKeys)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const maxPackages = Math.max(1, opts.preflight.maxPackages || 20000);

    const { pmCommand } = ensureIgnoreScripts(opts.cmd);
    console.error(pcDim(`npm-malwatch preflight: running ${pmCommand.join(" ")}`));
    const code = await runPreflightInstall(pmCommand, process.cwd());
    if (code !== 0) process.exit(code);

    const report = scanNodeModulesForScripts(process.cwd(), {
      includePm: opts.preflight.includePm,
      maxPackages,
      scriptKeys
    });
    report.pmCommand = pmCommand;
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    const fmt = String(opts.preflight.format);
    if (fmt === "json") {
      // Print JSON only on stdout for machine use.
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatPreflightText(report));
      console.log("");
      console.log(pcDim(`Report written: ${reportPath}`));
    }
    return;
  }

  if (!opts.cmd.length) usageError("Missing command. Usage: npm-malwatch -- <command...>");

  const command = opts.cmd[0];
  const args = opts.cmd.slice(1);

  const preloadPath = findDistPreloadPath();
  if (!fs.existsSync(preloadPath)) {
    usageError(`Preload not found at ${preloadPath}.`);
  }

  const logFile = path.resolve(process.cwd(), opts.logFile ?? defaultLogFile());
  ensureDir(logFile);

  const session = `${Date.now()}-${process.pid}`;
  const env = {
    ...process.env,
    NPM_MALWATCH_LOG: logFile,
    NPM_MALWATCH_SESSION: session,
    NPM_MALWATCH_FILTER: "package-only",
    NPM_MALWATCH_INCLUDE_PM: opts.includePm ? "1" : "0",
    NPM_MALWATCH_HARDENING: opts.hardening === "off" ? "off" : "detect",
    NODE_OPTIONS: mergeNodeOptions(process.env.NODE_OPTIONS, preloadPath)
  };

  console.error(pcDim(`npm-malwatch: logging to ${logFile}`));
  const child = cp.spawn(command, args, { stdio: "inherit", env });
  const exitCode = await new Promise((resolve) => {
    child.on("exit", (code) => resolve(code ?? 0));
    child.on("error", () => resolve(1));
  });

  if (opts.summary) {
    try {
      const summary = await summarizeJsonl(logFile);
      if (opts.jsonSummary) {
        console.log(JSON.stringify(summary, null, 2));
      } else {
        console.log("");
        console.log(pcBold("npm-malwatch summary"));
        console.log(formatSummaryText(summary));
      }
    } catch (e) {
      console.error(pcYellow(`Failed to summarize log: ${e?.message ?? e}`));
    }
  }

  process.exit(exitCode);
}

main().catch((e) => {
  console.error(pcRed(String(e?.stack ?? e)));
  process.exit(1);
});
