import { safeToString } from "./internal.ts";

type SummaryCounts = {
  fs_read: number;
  fs_write: number;
  proc: number;
  dns: number;
  net: number;
};

export type Summary = {
  totalEvents: number;
  byPackage: Record<string, SummaryCounts>;
  topHosts: Array<{ host: string; count: number }>;
  topCommands: Array<{ cmd: string; count: number }>;
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

function normalizeCommand(cmd: unknown): string | null {
  const s = safeToString(cmd).trim();
  if (!s) return null;
  return s.length > 200 ? s.slice(0, 199) + "…" : s;
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

export async function summarizeJsonl(logFile: string): Promise<Summary> {
  const byPackage: Record<string, SummaryCounts> = {};
  const hosts = new Map<string, number>();
  const commands = new Map<string, number>();

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

    if (category === "net") {
      const host = normalizeHost(evt?.args?.host ?? evt?.args?.hostname);
      if (host) incMap(hosts, host);
    }
    if (category === "proc") {
      const cmd = normalizeCommand(evt?.args?.command ?? evt?.args?.file ?? evt?.args?.cmd);
      if (cmd) incMap(commands, cmd);
    }
  }

  return {
    totalEvents,
    byPackage,
    topHosts: topN(hosts, 10).map(({ key, count }) => ({ host: key, count })),
    topCommands: topN(commands, 10).map(({ key, count }) => ({ cmd: key, count }))
  };
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

  const maxRows = 50;
  const rows = pkgs.slice(0, maxRows);
  const hidden = pkgs.length - rows.length;

  lines.push(`${BOLD}By package (top ${rows.length})${RESET}`);

  const header = ["Package", "Total", "fs_r", "fs_w", "proc", "dns", "net"];
  const tableRows: string[][] = rows.map((r) => [
    r.pkg,
    String(r.total),
    String(r.fs_read),
    String(r.fs_write),
    String(r.proc),
    String(r.dns),
    String(r.net)
  ]);

  const maxPkgLen = 44;
  const truncatePkg = (s: string): string => (s.length > maxPkgLen ? s.slice(0, maxPkgLen - 1) + "…" : s);

  const widths = header.map((h, idx) => {
    const col = idx === 0 ? [h, ...tableRows.map((r) => truncatePkg(r[idx]!))] : [h, ...tableRows.map((r) => r[idx]!)];
    return Math.max(...col.map((s) => s.length));
  });

  const padRight = (s: string, w: number) => (s.length >= w ? s : s + " ".repeat(w - s.length));
  const padLeft = (s: string, w: number) => (s.length >= w ? s : " ".repeat(w - s.length) + s);

  const renderRow = (cols: string[], isHeader = false): string => {
    const rendered = cols.map((c, idx) => {
      const cell = idx === 0 ? truncatePkg(c) : c;
      const padded = idx === 0 ? padRight(cell, widths[idx]!) : padLeft(cell, widths[idx]!);
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

  if (hidden > 0) lines.push(`${DIM}… and ${hidden} more packages${RESET}`);

  if (summary.topHosts.length) {
    lines.push("");
    lines.push(`${BOLD}Top hosts (best-effort)${RESET}`);
    const wHost = Math.max("Host".length, ...summary.topHosts.map((h) => h.host.length));
    const wCount = Math.max("Count".length, ...summary.topHosts.map((h) => String(h.count).length));
    const sep2 = `+-${"-".repeat(wHost)}-+-${"-".repeat(wCount)}-+`;
    lines.push(`${DIM}${sep2}${RESET}`);
    lines.push(`${BOLD}| ${"Host".padEnd(wHost)} | ${"Count".padStart(wCount)} |${RESET}`);
    lines.push(`${DIM}${sep2}${RESET}`);
    for (const { host, count } of summary.topHosts) {
      lines.push(`| ${host.padEnd(wHost)} | ${String(count).padStart(wCount)} |`);
    }
    lines.push(`${DIM}${sep2}${RESET}`);
  }
  if (summary.topCommands.length) {
    lines.push("");
    lines.push(`${BOLD}Top commands (best-effort)${RESET}`);
    for (const { cmd, count } of summary.topCommands) lines.push(`- ${cmd} ${DIM}(${count})${RESET}`);
  }
  return lines.join("\n");
}
