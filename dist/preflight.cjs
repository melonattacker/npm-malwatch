"use strict";

const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const {
  classifyPackageDisplayName,
  isPmPackageName,
  safeToString,
  truncateString
} = require('./internal.cjs');

function ensureIgnoreScripts(cmd) {
  if (cmd.length === 0) return { pmCommand: cmd, injected: false };
  const hasIgnore = cmd.includes('--ignore-scripts');
  if (hasIgnore) return { pmCommand: cmd, injected: false };

  // Only inject for install-like commands where it makes sense.
  // Conditions:
  // - 2nd token is one of: install, i, add, ci
  // - or any token equals these verbs (conservative and safe)
  const verbs = new Set(['install', 'i', 'add', 'ci']);
  const installLike = verbs.has(cmd[1] ?? '') || cmd.some((t) => verbs.has(t));
  if (!installLike) return { pmCommand: cmd, injected: false };
  return { pmCommand: [...cmd, '--ignore-scripts'], injected: true };
}

async function runPreflightInstall(cmd, cwd) {
  if (cmd.length === 0) return 2;
  const child = cp.spawn(cmd[0], cmd.slice(1), {
    stdio: 'inherit',
    cwd,
    env: { ...process.env }
  });
  return await new Promise((resolve) => {
    child.on('exit', (code) => resolve(code ?? 0));
    child.on('error', () => resolve(1));
  });
}

function safeReadJson(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function pickScripts(scripts, keys) {
  const out = {};
  if (!scripts || typeof scripts !== 'object') return out;
  for (const key of keys) {
    const v = scripts[key];
    if (typeof v === 'string' && v.trim()) out[key] = truncateString(v.trim(), 1000);
  }
  return out;
}

function listNpmStylePackageJsonPaths(nodeModulesRoot, max) {
  const out = [];
  if (!fs.existsSync(nodeModulesRoot)) return out;

  let entries;
  try {
    entries = fs.readdirSync(nodeModulesRoot, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const e of entries) {
    if (out.length >= max) break;
    if (!e.isDirectory()) continue;
    if (e.name === '.bin' || e.name === '.pnpm') continue;

    const full = path.join(nodeModulesRoot, e.name);
    if (e.name.startsWith('@')) {
      let scoped;
      try {
        scoped = fs.readdirSync(full, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const se of scoped) {
        if (out.length >= max) break;
        if (!se.isDirectory()) continue;
        out.push(path.join(full, se.name, 'package.json'));
      }
    } else {
      out.push(path.join(full, 'package.json'));
    }
  }

  return out;
}

function listPnpmStylePackageJsonPaths(nodeModulesRoot, max) {
  const out = [];
  const pnpmRoot = path.join(nodeModulesRoot, '.pnpm');
  if (!fs.existsSync(pnpmRoot)) return out;

  let entries;
  try {
    entries = fs.readdirSync(pnpmRoot, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const storeEntry of entries) {
    if (out.length >= max) break;
    if (!storeEntry.isDirectory()) continue;
    const nm = path.join(pnpmRoot, storeEntry.name, 'node_modules');
    const paths = listNpmStylePackageJsonPaths(nm, max - out.length);
    for (const p of paths) {
      if (out.length >= max) break;
      out.push(p);
    }
  }

  return out;
}

function scanNodeModulesForScripts(cwd, opts) {
  const nodeModulesRoot = path.join(cwd, 'node_modules');
  const max = opts.maxPackages;
  const scriptKeys = opts.scriptKeys;

  const pkgJsonPaths = [];
  const npmPaths = listNpmStylePackageJsonPaths(nodeModulesRoot, max);
  for (const p of npmPaths) pkgJsonPaths.push(p);
  const pnpmPaths = listPnpmStylePackageJsonPaths(nodeModulesRoot, Math.max(0, max - pkgJsonPaths.length));
  for (const p of pnpmPaths) pkgJsonPaths.push(p);

  const packages = [];
  let parseErrors = 0;
  let truncated = false;

  for (const pkgJsonPath of pkgJsonPaths) {
    if (packages.length >= max) {
      truncated = true;
      break;
    }
    if (!fs.existsSync(pkgJsonPath)) continue;
    const data = safeReadJson(pkgJsonPath);
    if (!data) {
      parseErrors++;
      continue;
    }

    const name = typeof data.name === 'string' ? data.name : path.basename(path.dirname(pkgJsonPath));
    const version = typeof data.version === 'string' ? data.version : '';
    const scripts = pickScripts(data.scripts, scriptKeys);
    if (Object.keys(scripts).length === 0) continue;

    const display = classifyPackageDisplayName(name);
    if (!opts.includePm) {
      const pm = isPmPackageName(name);
      if (pm) continue;
      if (display.startsWith('<pm:')) continue;
    }

    packages.push({
      name: display,
      version: safeToString(version),
      path: path.dirname(pkgJsonPath),
      scripts
    });
  }

  return {
    ts: Date.now(),
    cwd,
    pmCommand: [],
    nodeModulesRoot,
    totalPackagesScanned: pkgJsonPaths.length,
    packagesWithScripts: packages.length,
    scriptKeys,
    packages,
    parseErrors,
    truncated
  };
}

function formatPreflightText(report) {
  const lines = [];
  lines.push(`node_modules: ${report.nodeModulesRoot}`);
  lines.push(`packages scanned: ${report.totalPackagesScanned}`);
  lines.push(`packages with scripts: ${report.packagesWithScripts}`);
  if (report.parseErrors) lines.push(`package.json parse errors: ${report.parseErrors}`);
  if (report.truncated) lines.push('warning: truncated (max-packages reached)');
  lines.push('');

  const pkgs = [...report.packages].sort((a, b) => a.name.localeCompare(b.name));
  for (const p of pkgs) {
    lines.push(`- ${p.name}${p.version ? '@' + p.version : ''}`);
    lines.push(`  path: ${p.path}`);
    for (const [k, v] of Object.entries(p.scripts)) {
      lines.push(`  ${k}: ${v}`);
    }
  }
  return lines.join('\n');
}

module.exports = {
  ensureIgnoreScripts,
  runPreflightInstall,
  scanNodeModulesForScripts,
  formatPreflightText
};

