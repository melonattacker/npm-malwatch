import { classifyPackageDisplayName, isPmPackageName, safeToString, truncateString } from "./internal.ts";
import { join, dirname, basename } from "./path.ts";

export type PreflightPackage = {
  name: string;
  version: string;
  path: string;
  scripts: Record<string, string>;
};

export type PreflightReport = {
  ts: number;
  cwd: string;
  pmCommand: string[];
  nodeModulesRoot: string;
  totalPackagesScanned: number;
  packagesWithScripts: number;
  scriptKeys: string[];
  packages: PreflightPackage[];
  parseErrors: number;
  truncated: boolean;
};

export type PreflightOptions = {
  includePm: boolean;
  maxPackages: number;
  scriptKeys: string[];
};

export function ensureIgnoreScripts(cmd: string[]): { pmCommand: string[]; injected: boolean } {
  if (cmd.length === 0) return { pmCommand: cmd, injected: false };
  if (cmd.includes("--ignore-scripts")) return { pmCommand: cmd, injected: false };

  // Only inject for install-like commands where it makes sense.
  const verbs = new Set(["install", "i", "add", "ci"]);
  const installLike = verbs.has(cmd[1] ?? "") || cmd.some((t) => verbs.has(t));
  if (!installLike) return { pmCommand: cmd, injected: false };
  return { pmCommand: [...cmd, "--ignore-scripts"], injected: true };
}

export async function runPreflightInstall(cmd: string[], cwd: string): Promise<number> {
  if (cmd.length === 0) return 2;
  const child = new Deno.Command(cmd[0]!, {
    args: cmd.slice(1),
    cwd,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
    env: { ...Deno.env.toObject() }
  }).spawn();
  const status = await child.status;
  return status.code;
}

function safeReadJson(filePath: string): any | null {
  try {
    const raw = Deno.readTextFileSync(filePath);
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function pickScripts(scripts: any, keys: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  if (!scripts || typeof scripts !== "object") return out;
  for (const key of keys) {
    const v = scripts[key];
    if (typeof v === "string" && v.trim()) out[key] = truncateString(v.trim(), 1000);
  }
  return out;
}

function listNpmStylePackageJsonPaths(nodeModulesRoot: string, max: number): string[] {
  const out: string[] = [];
  try {
    if (!Deno.statSync(nodeModulesRoot).isDirectory) return out;
  } catch {
    return out;
  }

  try {
    const entries = [...Deno.readDirSync(nodeModulesRoot)].sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (out.length >= max) break;
      if (!e.isDirectory) continue;
      if (e.name === ".bin" || e.name === ".pnpm") continue;

      const full = join(nodeModulesRoot, e.name);
      if (e.name.startsWith("@")) {
        try {
          const scopedEntries = [...Deno.readDirSync(full)].sort((a, b) => a.name.localeCompare(b.name));
          for (const se of scopedEntries) {
            if (out.length >= max) break;
            if (!se.isDirectory) continue;
            out.push(join(full, se.name, "package.json"));
          }
        } catch {
          // ignore
        }
      } else {
        out.push(join(full, "package.json"));
      }
    }
  } catch {
    return out;
  }
  return out;
}

function listPnpmStylePackageJsonPaths(nodeModulesRoot: string, max: number): string[] {
  const out: string[] = [];
  const pnpmRoot = join(nodeModulesRoot, ".pnpm");
  try {
    if (!Deno.statSync(pnpmRoot).isDirectory) return out;
  } catch {
    return out;
  }

  try {
    const storeEntries = [...Deno.readDirSync(pnpmRoot)].sort((a, b) => a.name.localeCompare(b.name));
    for (const storeEntry of storeEntries) {
      if (out.length >= max) break;
      if (!storeEntry.isDirectory) continue;
      const nm = join(pnpmRoot, storeEntry.name, "node_modules");
      const paths = listNpmStylePackageJsonPaths(nm, max - out.length);
      for (const p of paths) {
        if (out.length >= max) break;
        out.push(p);
      }
    }
  } catch {
    return out;
  }
  return out;
}

export function scanNodeModulesForScripts(cwd: string, opts: PreflightOptions): PreflightReport {
  const nodeModulesRoot = join(cwd, "node_modules");
  const max = opts.maxPackages;
  const scriptKeys = opts.scriptKeys;

  const pkgJsonPaths: string[] = [];
  // Collect up to max+1 paths so we can signal truncation without unbounded scan.
  const limit = max + 1;
  pkgJsonPaths.push(...listNpmStylePackageJsonPaths(nodeModulesRoot, limit));
  if (pkgJsonPaths.length < limit) {
    pkgJsonPaths.push(...listPnpmStylePackageJsonPaths(nodeModulesRoot, limit - pkgJsonPaths.length));
  }

  const packages: PreflightPackage[] = [];
  let parseErrors = 0;
  const truncated = pkgJsonPaths.length > max;

  const toScan = pkgJsonPaths.slice(0, max);
  for (const pkgJsonPath of toScan) {
    try {
      if (!Deno.statSync(pkgJsonPath).isFile) continue;
    } catch {
      continue;
    }
    const data = safeReadJson(pkgJsonPath);
    if (!data) {
      parseErrors++;
      continue;
    }

    const rawName = typeof data.name === "string" ? data.name : basename(dirname(pkgJsonPath));
    const version = typeof data.version === "string" ? data.version : "";
    const scripts = pickScripts(data.scripts, scriptKeys);
    if (Object.keys(scripts).length === 0) continue;

    const display = classifyPackageDisplayName(rawName);
    if (!opts.includePm) {
      if (isPmPackageName(rawName)) continue;
      if (display.startsWith("<pm:")) continue;
    }

    packages.push({
      name: display,
      version: safeToString(version),
      path: dirname(pkgJsonPath),
      scripts
    });
  }

  return {
    ts: Date.now(),
    cwd,
    pmCommand: [],
    nodeModulesRoot,
    totalPackagesScanned: toScan.length,
    packagesWithScripts: packages.length,
    scriptKeys,
    packages,
    parseErrors,
    truncated
  };
}

export function formatPreflightText(report: PreflightReport): string {
  const useColor = Deno.isatty(Deno.stdout.rid);
  const BOLD = useColor ? "\x1b[1m" : "";
  const DIM = useColor ? "\x1b[2m" : "";
  const RESET = useColor ? "\x1b[0m" : "";

  const lines: string[] = [];
  lines.push(`${BOLD}node_modules:${RESET} ${report.nodeModulesRoot}`);
  lines.push(`${BOLD}packages scanned:${RESET} ${report.totalPackagesScanned}`);
  lines.push(`${BOLD}packages with scripts:${RESET} ${report.packagesWithScripts}`);
  if (report.parseErrors) lines.push(`${BOLD}package.json parse errors:${RESET} ${report.parseErrors}`);
  if (report.truncated) lines.push(`${DIM}warning: truncated (max-packages reached)${RESET}`);
  lines.push("");

  lines.push(`${BOLD}Scripts (preinstall/install/postinstall/prepare)${RESET}`);

  const rows: string[][] = [];
  const pkgs = [...report.packages].sort((a, b) => a.name.localeCompare(b.name));
  for (const p of pkgs) {
    const entries = Object.entries(p.scripts);
    for (const [k, v] of entries) {
      rows.push([p.name, p.version, k, v, p.path]);
    }
  }

  const header = ["Package", "Version", "Key", "Command", "Path"];

  const maxPkgLen = 28;
  const maxCmdLen = 80;
  const maxPathLen = 44;
  const truncate = (s: string, n: number): string => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  const widths = header.map((h, idx) => {
    const col = rows.map((r) => {
      const v = r[idx] ?? "";
      if (idx === 0) return truncate(v, maxPkgLen);
      if (idx === 3) return truncate(v, maxCmdLen);
      if (idx === 4) return truncate(v, maxPathLen);
      return v;
    });
    return Math.max(h.length, ...col.map((s) => s.length));
  });

  const padRight = (s: string, w: number) => (s.length >= w ? s : s + " ".repeat(w - s.length));
  const padLeft = (s: string, w: number) => (s.length >= w ? s : " ".repeat(w - s.length) + s);

  const renderRow = (cols: string[], isHeader = false): string => {
    const rendered = cols.map((c, idx) => {
      let cell = c ?? "";
      if (idx === 0) cell = truncate(cell, maxPkgLen);
      if (idx === 3) cell = truncate(cell, maxCmdLen);
      if (idx === 4) cell = truncate(cell, maxPathLen);
      const padded = (idx === 0 || idx === 1 || idx === 2 || idx === 3 || idx === 4) ? padRight(cell, widths[idx]!) : padLeft(cell, widths[idx]!);
      return padded;
    });
    const line = `| ${rendered.join(" | ")} |`;
    return isHeader ? `${BOLD}${line}${RESET}` : line;
  };

  const sep = `+-${widths.map((w) => "-".repeat(w)).join("-+-")}-+`;
  lines.push(`${DIM}${sep}${RESET}`);
  lines.push(renderRow(header, true));
  lines.push(`${DIM}${sep}${RESET}`);
  for (const r of rows) lines.push(renderRow(r));
  lines.push(`${DIM}${sep}${RESET}`);

  return lines.join("\n");
}

function csvEscape(value: string): string {
  if (!value) return "";
  if (/[",\n\r]/.test(value)) return `"${value.replaceAll(`"`, `""`)}"`;
  return value;
}

export function formatPreflightCsv(report: PreflightReport): string {
  const rows: string[] = [];
  rows.push(["package", "version", "key", "command", "path"].join(","));
  const pkgs = [...report.packages].sort((a, b) => a.name.localeCompare(b.name));
  for (const p of pkgs) {
    for (const [k, v] of Object.entries(p.scripts)) {
      rows.push([
        csvEscape(p.name),
        csvEscape(p.version),
        csvEscape(k),
        csvEscape(v),
        csvEscape(p.path)
      ].join(","));
    }
  }
  return rows.join("\n") + "\n";
}
