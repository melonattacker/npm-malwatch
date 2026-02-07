import { ensureIgnoreScripts, scanNodeModulesForScripts } from "./preflight.ts";
import { buildSandboxDockerRunArgs, defaultVolumeNames } from "./sandbox.ts";

function assert(condition: unknown, msg = "assertion failed"): asserts condition {
  if (!condition) throw new Error(msg);
}

function assertEquals(a: unknown, b: unknown, msg = "assertEquals failed"): void {
  if (a !== b) throw new Error(`${msg}: ${String(a)} !== ${String(b)}`);
}

function assertNotEquals(a: unknown, b: unknown, msg = "assertNotEquals failed"): void {
  if (a === b) throw new Error(`${msg}: both were ${String(a)}`);
}

function repoRootFromImportMeta(): string {
  // deno/npm-malwatch_test.ts -> deno/ -> repo root
  const u = new URL("..", import.meta.url);
  return decodeURIComponent(u.pathname);
}

type JsonlEvent = {
  op?: string;
  pkg?: string;
  category?: string;
  result?: string;
};

function readJsonlEvents(content: string): JsonlEvent[] {
  const out: JsonlEvent[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      // ignore
    }
  }
  return out;
}

function expectOps(events: JsonlEvent[], ops: string[]): void {
  const set = new Set(events.map((e) => e.op).filter(Boolean));
  for (const op of ops) {
    assert(set.has(op), `expected op missing: ${op}`);
  }
}

async function runObservedNode(
  js: string,
  opts?: { hardening?: "detect" | "off"; includePm?: boolean }
): Promise<{ logFile: string; content: string; events: JsonlEvent[] }> {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-observed-" });
  const logFile = `${tmp}/out.jsonl`;

  const root = repoRootFromImportMeta();
  const cli = `${root}/deno/npm-malwatch.ts`;

  const nodeCmd = Deno.env.get("NODE") || "node";
  const hardening = opts?.hardening ?? "detect";
  const includePm = opts?.includePm ?? false;

  const args = ["run", "-A", cli, "--log-file", logFile, "--no-summary", "--hardening", hardening];
  if (includePm) args.push("--include-pm");
  args.push("--", nodeCmd, "-e", js);

  const p = new Deno.Command(Deno.execPath(), {
    args,
    cwd: tmp,
    stdin: "null",
    stdout: "null",
    stderr: "null",
    env: { ...Deno.env.toObject() }
  }).spawn();

  const status = await p.status;
  assertEquals(status.code, 0, "deno npm-malwatch observed run failed");

  const content = await Deno.readTextFile(logFile);
  const events = readJsonlEvents(content);
  assert(events.length > 0, "expected some JSONL events");
  return { logFile, content, events };
}

Deno.test("observed mode captures core ops (fs sync/async/promises/stream + proc + dns + http + net)", async () => {
  const js = [
    "const fs = require('node:fs');",
    "const cp = require('node:child_process');",
    "const dns = require('node:dns');",
    "const http = require('node:http');",
    "const net = require('node:net');",
    "",
    "fs.writeFileSync('x.tmp','1');",
    "fs.readFileSync('x.tmp');",
    "",
    "fs.writeFile('y.tmp','2', () => {",
    "  fs.readFile('y.tmp', () => {",
    "    (async () => {",
    "      await fs.promises.writeFile('z.tmp','3');",
    "      await fs.promises.readFile('z.tmp');",
    "",
    "      const ws = fs.createWriteStream('s.tmp');",
    "      ws.end('4');",
    "      ws.on('finish', () => {",
    "        cp.spawnSync(process.execPath, ['-e','process.exit(0)'], { stdio: 'ignore' });",
    "",
    "        dns.lookup('localhost', () => {",
    "          const server = http.createServer((req,res) => res.end('ok'));",
    "          server.listen(0, '127.0.0.1', () => {",
    "            const port = server.address().port;",
    "            http.get({ host: '127.0.0.1', port, path: '/' }, (res) => {",
    "              res.resume();",
    "              res.on('end', () => {",
    "                const sock = net.createConnection({ host: '127.0.0.1', port }, () => {",
    "                  sock.end();",
    "                  server.close(() => process.exit(0));",
    "                });",
    "              });",
    "            }).on('error', () => process.exit(1));",
    "          });",
    "        });",
    "      });",
    "    })().catch(() => process.exit(1));",
    "  });",
    "});"
  ].join("\n");

  const { events } = await runObservedNode(js);
  expectOps(events, [
    "fs.writeFileSync",
    "fs.readFileSync",
    "fs.writeFile",
    "fs.readFile",
    "fs.promises.writeFile",
    "fs.promises.readFile",
    "fs.createWriteStream",
    "child_process.spawnSync",
    "dns.lookup"
  ]);
  // http.get and net.createConnection are best-effort; ensure at least one of each category appeared.
  assert(events.some((e) => e.op === "http.get" || e.op === "http.request"), "expected http.* op");
  assert(events.some((e) => e.op === "net.createConnection" || e.op === "net.connect"), "expected net.* op");

  // Attribution fallback should give a non-unknown pkg for at least one event.
  const firstNonStartup = events.find((e) => e.op && e.op !== "startup");
  assert(firstNonStartup?.pkg, "expected pkg field");
  assertNotEquals(firstNonStartup.pkg, "<unknown>", "expected pkg not <unknown>");
});

Deno.test("observed mode logs tamper when hooks are replaced (hardening=detect)", async () => {
  const js = [
    "const fs = require('node:fs');",
    "fs.writeFileSync = () => {};",
    "process.exit(0);"
  ].join("\n");
  const { events } = await runObservedNode(js, { hardening: "detect" });
  assert(events.some((e) => e.op === "tamper"), "expected tamper event");
});

Deno.test("ensureIgnoreScripts injects for install-like", () => {
  const { pmCommand, injected } = ensureIgnoreScripts(["pnpm", "install"]);
  assert(injected);
  assert(pmCommand.includes("--ignore-scripts"));
});

Deno.test("scanNodeModulesForScripts finds npm-style package.json scripts", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-deno-test-" });
  const nm = `${tmp}/node_modules/a`;
  await Deno.mkdir(nm, { recursive: true });
  await Deno.writeTextFile(
    `${nm}/package.json`,
    JSON.stringify({ name: "a", version: "1.0.0", scripts: { postinstall: "node install.js" } })
  );
  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ["postinstall"]
  });
  assertEquals(report.packagesWithScripts, 1);
  assertEquals(report.packages[0].name, "a");
});

Deno.test("preflight scan finds npm scoped + filters script keys", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-preflight-npm-" });
  await Deno.mkdir(`${tmp}/node_modules/@scope/pkg`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/@scope/pkg/package.json`,
    JSON.stringify({
      name: "@scope/pkg",
      version: "1.2.3",
      scripts: { postinstall: "echo post", prepare: "echo prep" }
    })
  );

  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ["prepare"]
  });
  assertEquals(report.packagesWithScripts, 1);
  assertEquals(report.packages[0].name, "@scope/pkg");
  assertEquals(Object.keys(report.packages[0].scripts).length, 1);
  assertEquals(report.packages[0].scripts.prepare, "echo prep");
});

Deno.test("preflight scan finds pnpm layout (scoped + unscoped)", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-preflight-pnpm-" });
  await Deno.mkdir(`${tmp}/node_modules/.pnpm/a@1.0.0/node_modules/a`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/.pnpm/a@1.0.0/node_modules/a/package.json`,
    JSON.stringify({ name: "a", version: "1.0.0", scripts: { install: "node -e \"\"" } })
  );

  await Deno.mkdir(`${tmp}/node_modules/.pnpm/@scope+pkg@1.0.0/node_modules/@scope/pkg`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/.pnpm/@scope+pkg@1.0.0/node_modules/@scope/pkg/package.json`,
    JSON.stringify({ name: "@scope/pkg", version: "1.0.0", scripts: { postinstall: "node post.js" } })
  );

  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ["install", "postinstall"]
  });
  const names = new Set(report.packages.map((p) => p.name));
  assert(names.has("a"), "expected unscoped pnpm package");
  assert(names.has("@scope/pkg"), "expected scoped pnpm package");
});

Deno.test("preflight scan excludes pm packages when includePm=false", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-preflight-pmfilter-" });
  await Deno.mkdir(`${tmp}/node_modules/npm`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/npm/package.json`,
    JSON.stringify({ name: "npm", version: "0.0.0", scripts: { postinstall: "echo hi" } })
  );
  await Deno.mkdir(`${tmp}/node_modules/@npmcli/foo`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/@npmcli/foo/package.json`,
    JSON.stringify({ name: "@npmcli/foo", version: "0.0.0", scripts: { install: "echo hi" } })
  );

  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ["install", "postinstall"]
  });
  assertEquals(report.packagesWithScripts, 0);
});

Deno.test("preflight scan counts parseErrors and supports maxPackages truncation", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-preflight-errors-" });

  // Sorted scan order is deterministic. Put a broken package first.
  await Deno.mkdir(`${tmp}/node_modules/0bad`, { recursive: true });
  await Deno.writeTextFile(`${tmp}/node_modules/0bad/package.json`, "{ not json");

  await Deno.mkdir(`${tmp}/node_modules/a`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/a/package.json`,
    JSON.stringify({ name: "a", version: "1.0.0", scripts: { postinstall: "echo a" } }),
  );

  await Deno.mkdir(`${tmp}/node_modules/b`, { recursive: true });
  await Deno.writeTextFile(
    `${tmp}/node_modules/b/package.json`,
    JSON.stringify({ name: "b", version: "1.0.0", scripts: { postinstall: "echo b" } }),
  );

  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 2,
    scriptKeys: ["postinstall"]
  });
  assert(report.parseErrors >= 1, "expected parseErrors >= 1");
  assert(report.truncated, "expected truncated=true");
  assertEquals(report.packagesWithScripts, 1);
});

Deno.test("sandbox docker args builder includes hardening isolation defaults and mounts", () => {
  const cwd = "/tmp/project";
  const vols = defaultVolumeNames(cwd);
  const args = buildSandboxDockerRunArgs({
    cwd,
    sandbox: {
      image: "node:22-bookworm-slim@sha256:5373f1906319b3a1f291da5d102f4ce5c77ccbe29eb637f072b6c7b70443fc36",
      observe: false,
      ephemeralVolumes: true,
      workVolume: vols.work,
      cacheVolume: vols.cache,
      network: "bridge",
      memory: "2g",
      cpus: "2",
      pidsLimit: 512
    },
    command: ["pnpm", "install"],
    runDirHostPath: "/tmp/project/.npm-malwatch/sandbox-x"
  });

  // basic docker run flags
  assert(args.includes("--read-only"));
  assert(args.includes("--cap-drop=ALL"));
  assert(args.includes("no-new-privileges"));
  assert(args.includes("--pids-limit"));
  assert(args.includes("512"));
  assert(args.includes("--network"));
  assert(args.includes("bridge"));
  // mounts
  assert(args.includes("-v"));
  assert(args.some((a) => a.includes(`${cwd}:/src:ro`)));
  assert(args.some((a) => a.includes(`${vols.work}:/work`)));
  assert(args.some((a) => a.includes(`${vols.cache}:/cache`)));
});

Deno.test("sandbox docker args builder sets observe env and mounts host log dir", () => {
  const cwd = "/tmp/project";
  const vols = defaultVolumeNames(cwd);
  const args = buildSandboxDockerRunArgs({
    cwd,
    sandbox: {
      image: "node:22-bookworm-slim@sha256:5373f1906319b3a1f291da5d102f4ce5c77ccbe29eb637f072b6c7b70443fc36",
      observe: true,
      ephemeralVolumes: true,
      workVolume: vols.work,
      cacheVolume: vols.cache,
      network: "bridge",
      memory: "2g",
      cpus: "2",
      pidsLimit: 512
    },
    command: ["pnpm", "rebuild"],
    runDirHostPath: "/tmp/project/.npm-malwatch/sandbox-x",
    observed: {
      preloadHostPath: "/tmp/project/.npm-malwatch/sandbox-x/preload.cjs",
      logHostPath: "/tmp/project/.npm-malwatch/sandbox-x/events.jsonl",
      session: "s",
      includePm: false,
      hardening: "detect"
    }
  });

  assert(args.some((a) => a.includes("/tmp/project/.npm-malwatch/sandbox-x:/opt/npm-malwatch")));
  assert(args.some((a) => a.includes("NPM_MALWATCH_LOG=/opt/npm-malwatch/events.jsonl")));
  assert(args.some((a) => a.includes("NODE_OPTIONS=--require /opt/npm-malwatch/preload.cjs")));
});
