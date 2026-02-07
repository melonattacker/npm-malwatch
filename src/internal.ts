import path from 'node:path';

export type MalwatchCategory = 'fs' | 'proc' | 'net' | 'dns' | 'tamper';
export type MalwatchResult = 'ok' | 'error';

export type MalwatchError = {
  name: string;
  message: string;
};

export type MalwatchEvent = {
  ts: number;
  session: string;
  pid: number;
  ppid: number;
  pkg: string;
  op: string;
  category: MalwatchCategory;
  args: Record<string, unknown>;
  result: MalwatchResult;
  error?: MalwatchError;
  stack?: string;
};

export function truncateString(value: string, maxLen: number): string {
  if (value.length <= maxLen) return value;
  return value.slice(0, Math.max(0, maxLen - 1)) + '…';
}

export function toPosixPath(p: string): string {
  return p.replaceAll('\\', '/');
}

function isProbablyFilePath(p: string): boolean {
  if (!p) return false;
  if (p.startsWith('node:')) return false;
  if (p.startsWith('internal/')) return false;
  if (p.startsWith('<')) return false;
  return true;
}

export function extractFilePathFromStackLine(line: string): string | null {
  const trimmed = line.trim();
  const m1 = trimmed.match(/\((.*):(\d+):(\d+)\)$/);
  if (m1?.[1] && isProbablyFilePath(m1[1])) return m1[1];
  const m2 = trimmed.match(/at (.*):(\d+):(\d+)$/);
  if (m2?.[1] && isProbablyFilePath(m2[1])) return m2[1];
  return null;
}

export function stackToCandidateFilePaths(stack?: string): string[] {
  if (!stack) return [];
  const lines = stack.split('\n');
  const out: string[] = [];
  for (const line of lines) {
    const fp = extractFilePathFromStackLine(line);
    if (!fp) continue;
    out.push(fp);
  }
  return out;
}

export function packageNameFromFilePath(filePath: string): string | null {
  const p = toPosixPath(filePath);
  const idx = p.lastIndexOf('/node_modules/');
  if (idx === -1) return null;

  const rest = p.slice(idx + '/node_modules/'.length);
  if (!rest || rest.startsWith('.')) return null;

  const parts = rest.split('/').filter(Boolean);
  if (parts.length === 0) return null;

  if (parts[0]?.startsWith('@')) {
    if (!parts[1]) return null;
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0] ?? null;
}

export function isPmPackageName(pkgName: string): 'npm' | 'pnpm' | null {
  if (pkgName === 'npm') return 'npm';
  if (pkgName === 'pnpm') return 'pnpm';
  if (pkgName.startsWith('@npmcli/')) return 'npm';
  if (pkgName.startsWith('@pnpm/')) return 'pnpm';
  return null;
}

export function classifyPackageDisplayName(pkgName: string): string {
  const pm = isPmPackageName(pkgName);
  if (pm === 'npm') return '<pm:npm>';
  if (pm === 'pnpm') return '<pm:pnpm>';
  return pkgName;
}

export function inferPackageFromStack(stack?: string): string {
  const candidates = stackToCandidateFilePaths(stack);
  for (const candidate of candidates) {
    const pkgName = packageNameFromFilePath(candidate);
    if (!pkgName) continue;
    if (pkgName === 'npm-malwatch') continue;
    return classifyPackageDisplayName(pkgName);
  }

  const envPkg = process.env.npm_package_name;
  if (envPkg) return classifyPackageDisplayName(envPkg);

  // If running outside node_modules, best-effort attribute to current project folder.
  const initCwd = process.env.INIT_CWD;
  const base = path.basename(initCwd || process.cwd());
  if (base) return base;

  return '<unknown>';
}

export function shortenStack(stack: string | undefined, maxLines: number, maxChars: number): string | undefined {
  if (!stack) return undefined;
  const lines = stack.split('\n').filter(Boolean);
  const kept: string[] = [];
  for (const line of lines) {
    if (line.includes('npm-malwatch') && line.includes('/dist/')) continue;
    kept.push(line);
    if (kept.length >= maxLines) break;
  }
  const joined = kept.join('\n');
  return truncateString(joined, maxChars);
}

function looksSensitiveKey(key: string): boolean {
  return /(pass|token|secret|auth|cookie|session)/i.test(key);
}

export function redactObject(value: unknown, maxDepth = 3): unknown {
  if (maxDepth <= 0) return '<truncated>';
  if (value === null) return null;
  if (value === undefined) return undefined;
  if (typeof value === 'string') return truncateString(value, 500);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactObject(v, maxDepth - 1));
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const keys = Object.keys(obj).slice(0, 40);
    for (const key of keys) {
      if (looksSensitiveKey(key)) {
        out[key] = '<redacted>';
      } else {
        out[key] = redactObject(obj[key], maxDepth - 1);
      }
    }
    return out;
  }
  return '<unserializable>';
}

export function safeToString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value instanceof URL) return value.toString();
  if (Buffer.isBuffer(value)) return '<buffer>';
  try {
    return String(value);
  } catch {
    return '<unstringifiable>';
  }
}
