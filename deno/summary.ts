import { safeToString } from "./internal.ts";

type SummaryCounts = {
  fs_read: number;
  fs_write: number;
  proc: number;
  dns: number;
  net: number;
};

type TopDetailPackage = { pkg: string; count: number };
type TopDetail = { key: string; count: number; packages: TopDetailPackage[] };

export type Summary = {
  totalEvents: number;
  byPackage: Record<string, SummaryCounts>;
  rootByPackage: Record<string, string | null>;
  topHosts: Array<{ host: string; count: number }>;
  topCommands: Array<{ cmd: string; count: number }>;
  topWritePaths: TopDetail[];
  topProcCommands: TopDetail[];
  topDnsHosts: TopDetail[];
  topNetHosts: TopDetail[];
};

function emptyCounts(): SummaryCounts {
  return { fs_read: 0, fs_write: 0, proc: 0, dns: 0, net: 0 };
}

function isFsReadOp(op: string): boolean {
  return op.startsWith("fs.read") || op.includes(".createReadStream") || op.includes("fs.promises.read");
}

function isFsWriteOp(op: string): boolean {
  return (
    op.startsWith("fs.write") ||
    op.startsWith("fs.append") ||
    op.includes(".createWriteStream") ||
    op.includes("fs.promises.write") ||
    op.includes("fs.promises.append")
  );
}

function normalizeHost(host: unknown): string | null {
  const s = safeToString(host).trim();
  if (!s) return null;
  return s;
}

function hostFromHref(href: unknown): string | null {
  const s = safeToString(href).trim();
  if (!s) return null;
  try {
    const u = new URL(s);
    return u.host || null;
  } catch {
    return null;
  }
}

function normalizeCommand(cmd: unknown): string | null {
  const s = safeToString(cmd).trim();
  if (!s) return null;
  return s.length > 200 ? s.slice(0, 199) + "…" : s;
}

function incNestedMap(map: Map<string, Map<string, number>>, outerKey: string, innerKey: string): void {
  const inner = map.get(outerKey) ?? new Map<string, number>();
  inner.set(innerKey, (inner.get(innerKey) ?? 0) + 1);
  map.set(outerKey, inner);
}

function incMap(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function topN(map: Map<string, number>, n: number): Array<{ key: string; count: number }> {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
}

function topNDetails(
  counts: Map<string, number>,
  pkgCounts: Map<string, Map<string, number>>,
  n: number,
  packagesTopN: number,
): TopDetail[] {
  const items = topN(counts, n);
  return items.map(({ key, count }) => {
    const inner = pkgCounts.get(key) ?? new Map<string, number>();
    const packages = [...inner.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, packagesTopN)
      .map(([pkg, c]) => ({ pkg, count: c }));
    return { key, count, packages };
  });
}

export async function summarizeJsonl(logFile: string): Promise<Summary> {
  const byPackage: Record<string, SummaryCounts> = {};
  const hosts = new Map<string, number>();
  const commands = new Map<string, number>();

  const writePaths = new Map<string, number>();
  const writePathPkgs = new Map<string, Map<string, number>>();
  const procCommandPkgs = new Map<string, Map<string, number>>();
  const dnsHosts = new Map<string, number>();
  const dnsHostPkgs = new Map<string, Map<string, number>>();
  const netHostPkgs = new Map<string, Map<string, number>>();

  // Avoid std imports; read whole file for now.
  const text = await Deno.readTextFile(logFile);
  const lines = text.split("\n");
  let totalEvents = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let evt: any;
    try {
      evt = JSON.parse(trimmed);
    } catch {
      continue;
    }
    totalEvents++;

    const pkg = typeof evt.pkg === "string" ? evt.pkg : "<unknown>";
    const op = typeof evt.op === "string" ? evt.op : "";
    const category = typeof evt.category === "string" ? evt.category : "";
    const counts = (byPackage[pkg] ??= emptyCounts());
    if (category === "fs") {
      if (isFsReadOp(op)) counts.fs_read++;
      else if (isFsWriteOp(op)) counts.fs_write++;
      else counts.fs_read++;
    } else if (category === "proc") {
      counts.proc++;
    } else if (category === "dns") {
      counts.dns++;
    } else if (category === "net") {
      counts.net++;
    }

    if (category === "fs" && isFsWriteOp(op)) {
      const p = typeof evt?.args?.path === "string" ? evt.args.path : null;
      if (p) {
        incMap(writePaths, p);
        incNestedMap(writePathPkgs, p, pkg);
      }
    }

    if (category === "net") {
      const host = normalizeHost(evt?.args?.host ?? evt?.args?.hostname) ?? hostFromHref(evt?.args?.href);
      if (host) {
        incMap(hosts, host);
        incNestedMap(netHostPkgs, host, pkg);
      }
    }
    if (category === "proc") {
      const file = typeof evt?.args?.file === "string" ? evt.args.file : null;
      const argv = Array.isArray(evt?.args?.argv) ? evt.args.argv : null;
      const composed = file && argv && argv.length ? `${file} ${argv.map((x: unknown) => safeToString(x)).join(" ")}` : null;
      const cmd = normalizeCommand(composed ?? evt?.args?.command ?? evt?.args?.file ?? evt?.args?.cmd);
      if (cmd) {
        incMap(commands, cmd);
        incNestedMap(procCommandPkgs, cmd, pkg);
      }
    }
    if (category === "dns") {
      const host = normalizeHost(evt?.args?.host);
      if (host) {
        incMap(dnsHosts, host);
        incNestedMap(dnsHostPkgs, host, pkg);
      }
    }
  }

  const rootByPackage: Record<string, string | null> = {};
  for (const pkg of Object.keys(byPackage)) rootByPackage[pkg] = null;

  return {
    totalEvents,
    byPackage,
    rootByPackage,
    topHosts: topN(hosts, 10).map(({ key, count }) => ({ host: key, count })),
    topCommands: topN(commands, 10).map(({ key, count }) => ({ cmd: key, count })),
    topWritePaths: topNDetails(writePaths, writePathPkgs, 10, 3),
    topProcCommands: topNDetails(commands, procCommandPkgs, 10, 3),
    topDnsHosts: topNDetails(dnsHosts, dnsHostPkgs, 10, 3),
    topNetHosts: topNDetails(hosts, netHostPkgs, 10, 3)
  };
}

function csvEscape(value: string): string {
  if (!value) return "";
  if (/[",\n\r]/.test(value)) return `"${value.replaceAll(`"`, `""`)}"`;
  return value;
}

export function formatSummaryCsv(summary: Summary): string {
  const header = ["root", "package", "total", "fs_read", "fs_write", "proc", "dns", "net"];
  const rows: string[] = [];
  rows.push(header.join(","));

  const pkgs = Object.entries(summary.byPackage)
    .map(([pkg, c]) => ({
      pkg,
      ...c,
      total: c.fs_read + c.fs_write + c.proc + c.dns + c.net
    }))
    .sort((a, b) => b.total - a.total);

  for (const r of pkgs) {
    rows.push([
      csvEscape(summary.rootByPackage[r.pkg] ?? ""),
      csvEscape(r.pkg),
      String(r.total),
      String(r.fs_read),
      String(r.fs_write),
      String(r.proc),
      String(r.dns),
      String(r.net)
    ].join(","));
  }

  return rows.join("\n") + "\n";
}

export function formatSummaryText(summary: Summary): string {
  const useColor = Deno.isatty(Deno.stdout.rid);
  const BOLD = useColor ? "\x1b[1m" : "";
  const DIM = useColor ? "\x1b[2m" : "";
  const RESET = useColor ? "\x1b[0m" : "";

  const lines: string[] = [];
  lines.push(`${BOLD}Total events:${RESET} ${summary.totalEvents}`);
  lines.push("");

  const pkgs = Object.entries(summary.byPackage)
    .map(([pkg, c]) => ({
      pkg,
      ...c,
      total: c.fs_read + c.fs_write + c.proc + c.dns + c.net
    }))
    .sort((a, b) => b.total - a.total);

  const rows = pkgs;
  lines.push(`${BOLD}By package${RESET}`);

  const header = ["Root", "Package", "Total", "fs_r", "fs_w", "proc", "dns", "net"];
  const tableRows: string[][] = rows.map((r) => [
    summary.rootByPackage[r.pkg] ?? "-",
    r.pkg,
    String(r.total),
    String(r.fs_read),
    String(r.fs_write),
    String(r.proc),
    String(r.dns),
    String(r.net)
  ]);

  const maxPkgLen = 36;
  const truncateCell = (s: string): string => (s.length > maxPkgLen ? s.slice(0, maxPkgLen - 1) + "…" : s);

  const widths = header.map((h, idx) => {
    const col = (idx === 0 || idx === 1)
      ? [h, ...tableRows.map((r) => truncateCell(r[idx]!))]
      : [h, ...tableRows.map((r) => r[idx]!)];
    return Math.max(...col.map((s) => s.length));
  });

  const padRight = (s: string, w: number) => (s.length >= w ? s : s + " ".repeat(w - s.length));
  const padLeft = (s: string, w: number) => (s.length >= w ? s : " ".repeat(w - s.length) + s);

  const renderRow = (cols: string[], isHeader = false): string => {
    const rendered = cols.map((c, idx) => {
      const cell = (idx === 0 || idx === 1) ? truncateCell(c) : c;
      const padded = (idx === 0 || idx === 1) ? padRight(cell, widths[idx]!) : padLeft(cell, widths[idx]!);
      return padded;
    });
    const line = `| ${rendered.join(" | ")} |`;
    return isHeader ? `${BOLD}${line}${RESET}` : line;
  };

  const sep = `+-${widths.map((w) => "-".repeat(w)).join("-+-")}-+`;
  lines.push(`${DIM}${sep}${RESET}`);
  lines.push(renderRow(header, true));
  lines.push(`${DIM}${sep}${RESET}`);
  for (const r of tableRows) lines.push(renderRow(r));
  lines.push(`${DIM}${sep}${RESET}`);

  // Intentionally list all packages for maximum visibility.

  const packagesCell = (pkgs: TopDetailPackage[]): string => {
    if (!pkgs.length) return "-";
    const s = pkgs.map((p) => `${p.pkg}(${p.count})`).join(", ");
    return s.length > 80 ? s.slice(0, 79) + "…" : s;
  };

  const valueTrunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  const renderDetailTable = (title: string, valueLabel: string, details: TopDetail[]): void => {
    if (!details.length) return;
    lines.push("");
    lines.push(`${BOLD}${title}${RESET}`);
    const header2 = [valueLabel, "Count", "Packages"];
    const rows2 = details.map((d) => [d.key, String(d.count), packagesCell(d.packages)]);
    const widths2 = header2.map((h, idx) => {
      const col = [
        h,
        ...rows2.map((r) => idx === 0 ? valueTrunc(r[idx]!, 60) : idx === 2 ? valueTrunc(r[idx]!, 80) : r[idx]!),
      ];
      return Math.max(...col.map((s) => s.length));
    });
    const sep2 = `+-${widths2.map((w) => "-".repeat(w)).join("-+-")}-+`;
    const padR = (s: string, w: number) => (s.length >= w ? s : s + " ".repeat(w - s.length));
    const padL = (s: string, w: number) => (s.length >= w ? s : " ".repeat(w - s.length) + s);
    const render = (cols: string[], isHeader = false) => {
      const rendered = cols.map((c, idx) => {
        const cell = idx === 0 ? valueTrunc(c, 60) : idx === 2 ? valueTrunc(c, 80) : c;
        const padded = idx === 1 ? padL(cell, widths2[idx]!) : padR(cell, widths2[idx]!);
        return padded;
      });
      const line = `| ${rendered.join(" | ")} |`;
      return isHeader ? `${BOLD}${line}${RESET}` : line;
    };

    lines.push(`${DIM}${sep2}${RESET}`);
    lines.push(render(header2, true));
    lines.push(`${DIM}${sep2}${RESET}`);
    for (const r of rows2) lines.push(render(r));
    lines.push(`${DIM}${sep2}${RESET}`);
  };

  lines.push("");
  lines.push(`${BOLD}Details (top 10)${RESET}`);
  renderDetailTable("Top file writes", "Path", summary.topWritePaths);
  renderDetailTable("Top spawned commands", "Command", summary.topProcCommands);
  renderDetailTable("Top DNS lookups", "Host", summary.topDnsHosts);
  renderDetailTable("Top network hosts", "Host", summary.topNetHosts);

  return lines.join("\n");
}
