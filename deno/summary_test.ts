import { formatSummaryText, summarizeJsonl } from "./summary.ts";

function assert(condition: unknown, msg = "assertion failed"): asserts condition {
  if (!condition) throw new Error(msg);
}

function assertEquals(a: unknown, b: unknown, msg = "assertEquals failed"): void {
  if (a !== b) throw new Error(`${msg}: ${String(a)} !== ${String(b)}`);
}

Deno.test("summary includes details tables (fs_w/proc/dns/net) with packages column", async () => {
  const tmp = await Deno.makeTempDir({ prefix: "npm-malwatch-summary-" });
  const logFile = `${tmp}/events.jsonl`;

  const base = {
    ts: 0,
    session: "s",
    pid: 1,
    ppid: 0,
    result: "ok"
  };

  const lines = [
    // fs_w (same path by multiple pkgs)
    { ...base, pkg: "a", op: "fs.writeFileSync", category: "fs", args: { path: "/tmp/x" } },
    { ...base, pkg: "a", op: "fs.writeFileSync", category: "fs", args: { path: "/tmp/x" } },
    { ...base, pkg: "b", op: "fs.writeFileSync", category: "fs", args: { path: "/tmp/x" } },
    // proc
    { ...base, pkg: "a", op: "child_process.spawnSync", category: "proc", args: { file: "node", argv: ["-e", "x"] } },
    // dns
    { ...base, pkg: "b", op: "dns.lookup", category: "dns", args: { host: "example.com" } },
    // net
    { ...base, pkg: "a", op: "http.get", category: "net", args: { host: "registry.npmjs.org" } }
  ].map((o) => JSON.stringify(o)).join("\n") + "\n";

  await Deno.writeTextFile(logFile, lines);

  const summary = await summarizeJsonl(logFile);
  assert(summary.topWritePaths.length >= 1, "expected topWritePaths");
  assertEquals(summary.topWritePaths[0].key, "/tmp/x");
  assert(summary.topWritePaths[0].packages.some((p) => p.pkg === "a" && p.count === 2), "expected a(2)");
  assert(summary.topWritePaths[0].packages.some((p) => p.pkg === "b" && p.count === 1), "expected b(1)");

  const text = formatSummaryText(summary);
  assert(text.includes("Details (top 10)"), "expected details header");
  assert(text.includes("Top file writes"), "expected file writes section");
  assert(text.includes("/tmp/x"), "expected path in details");
  assert(text.includes("a(2)"), "expected package count a(2)");
  assert(text.includes("b(1)"), "expected package count b(1)");
  assert(text.includes("Top spawned commands"), "expected proc section");
  assert(text.includes("node -e x") || text.includes("node"), "expected command in proc details");
  assert(text.includes("Top DNS lookups"), "expected dns section");
  assert(text.includes("example.com"), "expected dns host");
  assert(text.includes("Top network hosts"), "expected net section");
  assert(text.includes("registry.npmjs.org"), "expected net host");
});

