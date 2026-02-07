import { Command } from 'commander';
import cp from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import pc from 'picocolors';

import { formatSummaryText, summarizeJsonl } from './summary';
import {
  ensureIgnoreScripts,
  formatPreflightText,
  runPreflightInstall,
  scanNodeModulesForScripts
} from './preflight';

function findDistPreloadPath(): string {
  // dist/preload.cjs when built; during ts-node/dev, dist may not exist.
  const guess = path.resolve(__dirname, 'preload.cjs');
  if (fs.existsSync(guess)) return guess;
  // fallback (dev): resolve from project root
  const guess2 = path.resolve(process.cwd(), 'dist', 'preload.cjs');
  return guess2;
}

function defaultLogFile(): string {
  const dir = path.resolve(process.cwd(), '.npm-malwatch');
  const file = `${Date.now()}-${process.pid}.jsonl`;
  return path.join(dir, file);
}

function ensureDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function mergeNodeOptions(existing: string | undefined, preloadPath: string): string {
  const req = `--require ${JSON.stringify(preloadPath)}`;
  const base = existing?.trim() ? existing.trim() : '';
  if (base.includes(preloadPath) && base.includes('--require')) return base;
  if (!base) return req;
  return `${base} ${req}`;
}

function usageError(msg: string): never {
  // Commander throws, but we want consistent output.
  // eslint-disable-next-line no-console
  console.error(pc.red(`Error: ${msg}`));
  process.exit(2);
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name('npm-malwatch')
    .description('Visualize Node.js fs/process/network API usage during installs')
    .allowUnknownOption(true)
    .option('--log-file <path>', 'JSONL log output path')
    .option('--json-summary', 'Print summary as JSON')
    .option('--include-pm', 'Include events attributed to npm/pnpm itself')
    .option('--no-summary', 'Disable end-of-run summary')
    .option('--hardening <mode>', 'Hardening mode: detect|off', 'detect');

  program
    .command('preflight')
    .description('Run install with --ignore-scripts and list lifecycle scripts in node_modules')
    .allowUnknownOption(true)
    .option('--format <format>', 'text|json', 'text')
    .option('--output <path>', 'Write JSON report to path')
    .option('--include-pm', 'Include npm/pnpm scripts too', false)
    .option('--max-packages <n>', 'Max packages to scan', '20000')
    .option('--script-keys <csv>', 'Comma-separated script keys', 'preinstall,install,postinstall,prepare')
    .argument('[--]', 'Command separator')
    .action(async (_arg, cmd) => {
      const rawArgv = process.argv;
      const sepIndex = rawArgv.indexOf('--');
      const cmdArgs = sepIndex >= 0 ? rawArgv.slice(sepIndex + 1) : [];
      if (!cmdArgs.length) usageError('Missing command. Usage: npm-malwatch preflight -- <command...>');

      const reportPath = path.resolve(
        process.cwd(),
        cmd.output ?? path.join('.npm-malwatch', `preflight-${Date.now()}-${process.pid}.json`)
      );
      ensureDir(reportPath);

      const scriptKeys = String(cmd.scriptKeys)
        .split(',')
        .map((s: string) => s.trim())
        .filter(Boolean);
      const maxPackages = Math.max(1, Number.parseInt(String(cmd.maxPackages), 10) || 20000);
      const includePm = Boolean(cmd.includePm);

      const { pmCommand } = ensureIgnoreScripts(cmdArgs);
      // eslint-disable-next-line no-console
      console.error(pc.dim(`npm-malwatch preflight: running ${pmCommand.join(' ')}`));
      const code = await runPreflightInstall(pmCommand, process.cwd());
      if (code !== 0) {
        process.exit(code);
      }

      const report = scanNodeModulesForScripts(process.cwd(), {
        includePm,
        maxPackages,
        scriptKeys
      });
      report.pmCommand = pmCommand;

      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

      const fmt = String(cmd.format);
      if (fmt === 'json') {
        // Print JSON only on stdout for machine use.
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(report, null, 2));
      } else {
        // eslint-disable-next-line no-console
        console.log(formatPreflightText(report));
        // eslint-disable-next-line no-console
        console.log('');
        // eslint-disable-next-line no-console
        console.log(pc.dim(`Report written: ${reportPath}`));
      }
    });

  program.parse(process.argv);
  if (process.argv[2] === 'preflight') {
    return;
  }
  const opts = program.opts<{
    logFile?: string;
    jsonSummary?: boolean;
    includePm?: boolean;
    summary?: boolean;
    hardening?: string;
  }>();

  const dd = program.args;
  const sepIndex = process.argv.indexOf('--');
  const cmdArgs = sepIndex >= 0 ? process.argv.slice(sepIndex + 1) : dd;
  if (!cmdArgs.length) {
    usageError('Missing command. Usage: npm-malwatch -- <command...>');
  }

  const command = cmdArgs[0]!;
  const args = cmdArgs.slice(1);

  const preloadPath = findDistPreloadPath();
  if (!fs.existsSync(preloadPath)) {
    usageError(`Preload not found at ${preloadPath}. Run \`npm run build\` first.`);
  }

  const logFile = path.resolve(process.cwd(), opts.logFile ?? defaultLogFile());
  ensureDir(logFile);

  const session = `${Date.now()}-${process.pid}`;

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NPM_MALWATCH_LOG: logFile,
    NPM_MALWATCH_SESSION: session,
    NPM_MALWATCH_FILTER: 'package-only',
    NPM_MALWATCH_INCLUDE_PM: opts.includePm ? '1' : '0',
    NPM_MALWATCH_HARDENING: opts.hardening === 'off' ? 'off' : 'detect',
    NODE_OPTIONS: mergeNodeOptions(process.env.NODE_OPTIONS, preloadPath)
  };

  // eslint-disable-next-line no-console
  console.error(pc.dim(`npm-malwatch: logging to ${logFile}`));
  const child = cp.spawn(command, args, {
    stdio: 'inherit',
    env
  });

  const exitCode: number = await new Promise((resolve) => {
    child.on('exit', (code) => resolve(code ?? 0));
    child.on('error', () => resolve(1));
  });

  if (opts.summary !== false) {
    try {
      const summary = await summarizeJsonl(logFile);
      if (opts.jsonSummary) {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(summary, null, 2));
      } else {
        // eslint-disable-next-line no-console
        console.log('');
        // eslint-disable-next-line no-console
        console.log(pc.bold('npm-malwatch summary'));
        // eslint-disable-next-line no-console
        console.log(formatSummaryText(summary));
      }
    } catch (e: any) {
      // eslint-disable-next-line no-console
      console.error(pc.yellow(`Failed to summarize log: ${e?.message ?? e}`));
    }
  }

  process.exit(exitCode);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(pc.red(String(e?.stack ?? e)));
  process.exit(1);
});
