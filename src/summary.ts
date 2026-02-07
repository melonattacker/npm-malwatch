import fs from 'node:fs';
import readline from 'node:readline';
import { safeToString } from './internal';

type SummaryCounts = {
  fs_read: number;
  fs_write: number;
  proc: number;
  dns: number;
  net: number;
};

type Summary = {
  totalEvents: number;
  byPackage: Record<string, SummaryCounts>;
  topHosts: Array<{ host: string; count: number }>; // best-effort
  topCommands: Array<{ cmd: string; count: number }>;
};

function emptyCounts(): SummaryCounts {
  return { fs_read: 0, fs_write: 0, proc: 0, dns: 0, net: 0 };
}

function isFsReadOp(op: string): boolean {
  return (
    op.startsWith('fs.read') ||
    op.includes('.createReadStream') ||
    op.includes('fs.promises.read')
  );
}

function isFsWriteOp(op: string): boolean {
  return (
    op.startsWith('fs.write') ||
    op.startsWith('fs.append') ||
    op.includes('.createWriteStream') ||
    op.includes('fs.promises.write') ||
    op.includes('fs.promises.append')
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
  return s.length > 200 ? s.slice(0, 199) + '…' : s;
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
  let totalEvents = 0;

  const input = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let evt: any;
    try {
      evt = JSON.parse(trimmed);
    } catch {
      continue;
    }

    totalEvents++;
    const pkg = typeof evt.pkg === 'string' ? evt.pkg : '<unknown>';
    const op = typeof evt.op === 'string' ? evt.op : '';
    const category = typeof evt.category === 'string' ? evt.category : '';

    const counts = (byPackage[pkg] ??= emptyCounts());
    if (category === 'fs') {
      if (isFsReadOp(op)) counts.fs_read++;
      else if (isFsWriteOp(op)) counts.fs_write++;
      else {
        // unknown fs; count as read by default to avoid hiding
        counts.fs_read++;
      }
    } else if (category === 'proc') {
      counts.proc++;
    } else if (category === 'dns') {
      counts.dns++;
    } else if (category === 'net') {
      counts.net++;
    }

    if (category === 'net') {
      const host = normalizeHost(evt?.args?.host ?? evt?.args?.hostname);
      if (host) incMap(hosts, host);
    }
    if (category === 'proc') {
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
  const lines: string[] = [];
  lines.push(`Total events: ${summary.totalEvents}`);
  lines.push('');
  lines.push('By package (counts):');
  const pkgs = Object.entries(summary.byPackage)
    .sort((a, b) => {
      const ta = a[1].fs_read + a[1].fs_write + a[1].proc + a[1].dns + a[1].net;
      const tb = b[1].fs_read + b[1].fs_write + b[1].proc + b[1].dns + b[1].net;
      return tb - ta;
    });
  for (const [pkg, c] of pkgs) {
    lines.push(
      `- ${pkg}: fs_read=${c.fs_read} fs_write=${c.fs_write} proc=${c.proc} dns=${c.dns} net=${c.net}`
    );
  }
  if (summary.topHosts.length) {
    lines.push('');
    lines.push('Top hosts (best-effort):');
    for (const { host, count } of summary.topHosts) {
      lines.push(`- ${host}: ${count}`);
    }
  }
  if (summary.topCommands.length) {
    lines.push('');
    lines.push('Top commands (best-effort):');
    for (const { cmd, count } of summary.topCommands) {
      lines.push(`- ${cmd}: ${count}`);
    }
  }
  return lines.join('\n');
}

