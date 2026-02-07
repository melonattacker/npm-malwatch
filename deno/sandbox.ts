import { basename, dirname, join, resolve } from "./path.ts";

export type SandboxOptions = {
  image: string;
  observe: boolean;
  ephemeralVolumes: boolean;
  workVolume: string;
  cacheVolume: string;
  network: string;
  memory: string;
  cpus: string;
  pidsLimit: number;
};

export type SandboxObservedEnv = {
  preloadHostPath: string;
  logHostPath: string;
  session: string;
  includePm: boolean;
  hardening: "detect" | "off";
};

export function fnv1aHex(input: string): string {
  // 32-bit FNV-1a
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export function defaultVolumeNames(cwd: string): { work: string; cache: string } {
  const h = fnv1aHex(cwd);
  return {
    work: `npm-malwatch-work-${h}`,
    cache: `npm-malwatch-cache-${h}`
  };
}

function dockerTmpfsArgs(target: string, size: string): string[] {
  return ["--tmpfs", `${target}:rw,nosuid,nodev,noexec,size=${size}`];
}

export function buildSandboxDockerRunArgs(params: {
  cwd: string;
  sandbox: SandboxOptions;
  command: string[];
  runDirHostPath: string;
  observed?: SandboxObservedEnv;
}): string[] {
  const { cwd, sandbox, command, runDirHostPath, observed } = params;
  if (!command.length) throw new Error("missing command");

  const args: string[] = ["run", "--rm"];

  // Isolation / limits (safe-ish defaults).
  args.push("--read-only");
  args.push("--cap-drop=ALL");
  args.push("--security-opt", "no-new-privileges");
  args.push("--pids-limit", String(sandbox.pidsLimit));
  args.push("--memory", sandbox.memory);
  args.push("--cpus", sandbox.cpus);
  args.push("--network", sandbox.network);

  // Writable areas.
  args.push(...dockerTmpfsArgs("/tmp", "1g"));
  args.push(...dockerTmpfsArgs("/run", "64m"));
  // npm/pnpm/corepack often want to write under $HOME.
  args.push(...dockerTmpfsArgs("/home/node", "1g"));

  // Workdir.
  args.push("--workdir", "/work");

  // Mounts.
  // `cwd` should be absolute (Deno.cwd()).
  args.push("-v", `${cwd}:/src:ro`);
  args.push("-v", `${sandbox.workVolume}:/work`);
  args.push("-v", `${sandbox.cacheVolume}:/cache`);

  // Observed mode mounts (bind run dir for logs + preload).
  if (sandbox.observe && observed) {
    const bindHostDir = dirname(resolve(cwd, observed.logHostPath));
    args.push("-v", `${bindHostDir}:/opt/npm-malwatch`);
    args.push("-e", `NPM_MALWATCH_LOG=/opt/npm-malwatch/${basename(observed.logHostPath)}`);
    args.push("-e", `NPM_MALWATCH_SESSION=${observed.session}`);
    args.push("-e", "NPM_MALWATCH_FILTER=package-only");
    args.push("-e", `NPM_MALWATCH_INCLUDE_PM=${observed.includePm ? "1" : "0"}`);
    args.push("-e", `NPM_MALWATCH_HARDENING=${observed.hardening}`);
    args.push("-e", "NODE_OPTIONS=--require /opt/npm-malwatch/preload.cjs");
  }

  // Common cache env.
  args.push("-e", "HOME=/home/node");
  args.push("-e", "NPM_CONFIG_CACHE=/cache/npm");
  args.push("-e", "COREPACK_HOME=/cache/corepack");

  // Image.
  args.push(sandbox.image);

  // Container command: copy /src to /work if needed, setup caches, ensure pnpm if requested.
  const script = [
    "set -eu",
    // Initialize /work once.
    'if [ ! -f "/work/package.json" ] && [ -d "/src" ]; then',
    "  # best-effort cleanup (ignore dotfiles errors)",
    "  rm -rf /work/* /work/.[!.]* /work/..?* 2>/dev/null || true",
    "  cp -a /src/. /work/",
    "fi",
    "mkdir -p /cache/npm /cache/pnpm /cache/corepack /cache/npm-global/bin",
    // Ensure pnpm availability without writing to rootfs.
    'cmd="$1"; shift',
    'if [ "$cmd" = "pnpm" ]; then',
    "  export PATH=/cache/npm-global/bin:$PATH",
    "  if ! command -v pnpm >/dev/null 2>&1; then",
    "    (corepack enable >/dev/null 2>&1 || true)",
    "  fi",
    "  if ! command -v pnpm >/dev/null 2>&1; then",
    "    npm -s i -g pnpm@latest --prefix /cache/npm-global >/dev/null 2>&1 || npm -s i -g pnpm --prefix /cache/npm-global",
    "  fi",
    "  pnpm config set store-dir /cache/pnpm >/dev/null 2>&1 || true",
    "fi",
    // Execute user command.
    'exec "$cmd" "$@"'
  ].join("\n");

  // Provide original command as "$@" after a sentinel.
  args.push("sh", "-lc", script, "--", command[0]!, ...command.slice(1));

  return args;
}

export function defaultRunDir(cwd: string): string {
  return join(cwd, ".npm-malwatch", `sandbox-${Date.now()}-${Deno.pid}`);
}
