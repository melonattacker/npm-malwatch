// This module provides a single-file CommonJS preload script (as a string)
// that Node can `--require` to hook dangerous APIs and append JSONL logs.
//
// It is generated at runtime into a temp directory by the Deno CLI.

export const PRELOAD_CJS = `"use strict";

// Runs inside the target Node.js process via --require.
const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const childProcess = require("node:child_process");
const { AsyncLocalStorage } = require("node:async_hooks");
const Module = require("node:module");

const SESSION = process.env.NPM_MALWATCH_SESSION || \`\${Date.now()}-\${process.pid}\`;
const LOG_FILE = process.env.NPM_MALWATCH_LOG;
const FILTER = process.env.NPM_MALWATCH_FILTER || "package-only";
const INCLUDE_PM = process.env.NPM_MALWATCH_INCLUDE_PM === "1";
const HARDENING = process.env.NPM_MALWATCH_HARDENING || "detect";

const STACK_LINES = 12;
const STACK_CHARS = 2000;

const pkgAls = new AsyncLocalStorage();

function truncateString(value, maxLen) {
  if (value.length <= maxLen) return value;
  return value.slice(0, Math.max(0, maxLen - 1)) + "…";
}

function safeToString(value) {
  if (typeof value === "string") return value;
  if (value instanceof URL) return value.toString();
  if (Buffer.isBuffer(value)) return "<buffer>";
  try { return String(value); } catch { return "<unstringifiable>"; }
}

function toPosixPath(p) { return p.replaceAll("\\\\", "/"); }

function extractFilePathFromStackLine(line) {
  const trimmed = line.trim();
  const m1 = trimmed.match(/\\((.*):(\\d+):(\\d+)\\)$/);
  if (m1?.[1]) return m1[1];
  const m2 = trimmed.match(/at (.*):(\\d+):(\\d+)$/);
  if (m2?.[1]) return m2[1];
  return null;
}

function packageNameFromFilePath(filePath) {
  const p = toPosixPath(filePath);
  const idx = p.lastIndexOf("/node_modules/");
  if (idx === -1) return null;
  const rest = p.slice(idx + "/node_modules/".length);
  if (!rest || rest.startsWith(".")) return null;
  const parts = rest.split("/").filter(Boolean);
  if (parts.length === 0) return null;
  if (parts[0]?.startsWith("@")) {
    if (!parts[1]) return null;
    return \`\${parts[0]}/\${parts[1]}\`;
  }
  return parts[0] ?? null;
}

function isPmPackageName(pkgName) {
  if (pkgName === "npm") return "npm";
  if (pkgName === "pnpm") return "pnpm";
  if (pkgName.startsWith("@npmcli/")) return "npm";
  if (pkgName.startsWith("@pnpm/")) return "pnpm";
  return null;
}

function classifyPackageDisplayName(pkgName) {
  const pm = isPmPackageName(pkgName);
  if (pm === "npm") return "<pm:npm>";
  if (pm === "pnpm") return "<pm:pnpm>";
  return pkgName;
}

function inferPackageFromStack(stack) {
  const lines = (stack || "").split("\\n");
  for (const line of lines) {
    const fp = extractFilePathFromStackLine(line);
    if (!fp) continue;
    const pkgName = packageNameFromFilePath(fp);
    if (!pkgName) continue;
    if (pkgName === "npm-malwatch") continue;
    return classifyPackageDisplayName(pkgName);
  }
  return "<unknown>";
}

function shortenStack(stack) {
  if (!stack) return void 0;
  const lines = stack.split("\\n").filter(Boolean).slice(0, STACK_LINES);
  return truncateString(lines.join("\\n"), STACK_CHARS);
}

function looksSensitiveKey(key) { return /(pass|token|secret|auth|cookie|session)/i.test(key); }

function redactObject(value, maxDepth = 3) {
  if (maxDepth <= 0) return "<truncated>";
  if (value === null) return null;
  if (value === void 0) return void 0;
  if (typeof value === "string") return truncateString(value, 500);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactObject(v, maxDepth - 1));
  if (typeof value === "object") {
    const obj = value;
    const out = {};
    const keys = Object.keys(obj).slice(0, 40);
    for (const key of keys) {
      out[key] = looksSensitiveKey(key) ? "<redacted>" : redactObject(obj[key], maxDepth - 1);
    }
    return out;
  }
  return "<unserializable>";
}

const DEFAULT_LOG_DIR = path.join(process.cwd(), ".npm-malwatch");
const DEFAULT_LOG_FILE = path.join(DEFAULT_LOG_DIR, \`\${Date.now()}-\${process.pid}.jsonl\`);
const logFilePath = LOG_FILE || DEFAULT_LOG_FILE;

// Keep original references early.
const realFs = { ...fs };
const realDns = { ...dns };
const realNet = { ...net };
const realChild = { ...childProcess };

let logFd = null;
function ensureLogFd() {
  if (logFd !== null) return logFd;
  try { realFs.mkdirSync(path.dirname(logFilePath), { recursive: true }); } catch {}
  logFd = realFs.openSync(logFilePath, "a");
  return logFd;
}
function writeLine(line) {
  const fd = ensureLogFd();
  try { realFs.writeSync(fd, line + "\\n"); } catch {}
}

function shouldEmitForPackage(pkg) {
  if (INCLUDE_PM) return true;
  if (pkg.startsWith("<pm:")) return false;
  return true;
}

function shouldEmitEvent(pkg) {
  if (FILTER !== "package-only") return true;
  if (pkg === "<malwatch>") return false;
  if (!shouldEmitForPackage(pkg)) return false;
  return true;
}

function logEvent(partial) {
  const evt = {
    ts: Date.now(),
    session: SESSION,
    pid: process.pid,
    ppid: typeof process.ppid === "number" ? process.ppid : -1,
    ...partial
  };
  if (!shouldEmitEvent(evt.pkg)) return;
  writeLine(JSON.stringify(evt));
}

// Track "current package" via the CommonJS module loader and propagate it across
// async boundaries. This is best-effort and not perfect.
const realModuleLoad = Module._load;
const realResolveFilename = Module._resolveFilename;
try {
  Module._load = function (request, parent, isMain) {
    let resolved = null;
    try {
      resolved = realResolveFilename(request, parent, isMain);
    } catch {
      return realModuleLoad.apply(this, arguments);
    }

    const pkgNameRaw = typeof resolved === "string" ? packageNameFromFilePath(resolved) : null;
    const pkgName = pkgNameRaw ? classifyPackageDisplayName(pkgNameRaw) : null;

    if (typeof pkgName === "string") {
      return pkgAls.run(pkgName, () => realModuleLoad.apply(this, arguments));
    }
    return realModuleLoad.apply(this, arguments);
  };
} catch {}

function baseArgs(args) { return { argv: redactObject(args) }; }

function currentPkgAndMaybeStack() {
  const store = pkgAls.getStore();
  if (typeof store === "string") return { pkg: store, stack: null };
  const stack = new Error("stack").stack;
  return { pkg: inferPackageFromStack(stack), stack };
}

function wrapSync(category, op, original, makeArgs = (...args) => baseArgs(args)) {
  const wrapped = function (...args) {
    const { pkg, stack } = currentPkgAndMaybeStack();
    const evBase = { pkg, op, category, args: makeArgs(...args) };
    try {
      const result = original.apply(this, args);
      logEvent({ ...evBase, result: "ok", stack: stack ? shortenStack(stack) : void 0 });
      return result;
    } catch (e) {
      const errStack = stack || new Error("stack").stack;
      logEvent({
        ...evBase,
        result: "error",
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(errStack)
      });
      throw e;
    }
  };
  wrapped.__npm_malwatch_wrapped__ = { category, op };
  return wrapped;
}

function wrapAsync(category, op, original, makeArgs = (...args) => baseArgs(args)) {
  const wrapped = function (...args) {
    const { pkg, stack } = currentPkgAndMaybeStack();
    const evBase = { pkg, op, category, args: makeArgs(...args) };
    try {
      const result = original.apply(this, args);
      if (result && typeof result.then === "function") {
        return result.then((v) => {
          logEvent({ ...evBase, result: "ok", stack: stack ? shortenStack(stack) : void 0 });
          return v;
        })
          .catch((e) => {
            const errStack = stack || new Error("stack").stack;
            logEvent({
              ...evBase,
              result: "error",
              error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
              stack: shortenStack(errStack)
            });
            throw e;
          });
      }
      logEvent({ ...evBase, result: "ok", stack: stack ? shortenStack(stack) : void 0 });
      return result;
    } catch (e) {
      const errStack = stack || new Error("stack").stack;
      logEvent({
        ...evBase,
        result: "error",
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(errStack)
      });
      throw e;
    }
  };
  wrapped.__npm_malwatch_wrapped__ = { category, op };
  return wrapped;
}

function tryPatch(obj, key, value) { try { obj[key] = value; } catch {} }

function patchFs() {
  const wrapFs = (name, kind) => {
    const original = realFs[name];
    if (typeof original !== "function") return;
    const op = \`fs.\${String(name)}\`;
    const makeArgs = (...args) => ({ path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0, ...baseArgs(args) });
    const wrapped = kind === "sync" ? wrapSync("fs", op, original, makeArgs) : wrapAsync("fs", op, original, makeArgs);
    tryPatch(fs, name, wrapped);
  };
  const syncFns = ["readFileSync","writeFileSync","appendFileSync","readdirSync","statSync","lstatSync","readlinkSync","realpathSync","openSync","closeSync","chmodSync","chownSync","unlinkSync","mkdirSync","rmdirSync","rmSync","renameSync","copyFileSync"];
  for (const fn of syncFns) wrapFs(fn, "sync");
  const asyncFns = ["readFile","writeFile","appendFile","readdir","stat","lstat","readlink","realpath","open","close","chmod","chown","unlink","mkdir","rmdir","rm","rename","copyFile"];
  for (const fn of asyncFns) wrapFs(fn, "async");

  if (typeof realFs.createReadStream === "function") {
    tryPatch(fs, "createReadStream", wrapSync("fs", "fs.createReadStream", realFs.createReadStream, (...args) => ({ path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0, ...baseArgs(args) })));
  }
  if (typeof realFs.createWriteStream === "function") {
    tryPatch(fs, "createWriteStream", wrapSync("fs", "fs.createWriteStream", realFs.createWriteStream, (...args) => ({ path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0, ...baseArgs(args) })));
  }

  const p = fs.promises;
  const realP = realFs.promises;
  if (p && realP) {
    const promiseFns = ["readFile","writeFile","appendFile","readdir","stat","lstat","realpath","open","chmod","chown","unlink","mkdir","rm","rename","copyFile"];
    for (const fn of promiseFns) {
      if (typeof realP[fn] !== "function") continue;
      try {
        p[fn] = wrapAsync("fs", \`fs.promises.\${fn}\`, realP[fn].bind(realP), (...args) => ({ path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0, ...baseArgs(args) }));
      } catch {}
    }
  }
}

function patchChildProcess() {
  const patch = (name, op) => {
    const original = realChild[name];
    if (typeof original !== "function") return;
    const makeArgs = (...args) => {
      const [a0, a1] = args;
      if (name === "spawn" || name === "spawnSync" || name === "execFile" || name === "execFileSync" || name === "fork") {
        const file = typeof a0 === "string" ? truncateString(a0, 300) : void 0;
        const argv = Array.isArray(a1) ? a1.map((x) => truncateString(safeToString(x), 200)).slice(0, 20) : void 0;
        return { file, argv, ...baseArgs(args) };
      }
      const command = typeof a0 === "string" ? truncateString(a0, 400) : void 0;
      return { command, ...baseArgs(args) };
    };
    const wrapped = wrapSync("proc", op, original, makeArgs);
    tryPatch(childProcess, name, wrapped);
  };
  patch("spawn", "child_process.spawn");
  patch("spawnSync", "child_process.spawnSync");
  patch("exec", "child_process.exec");
  patch("execSync", "child_process.execSync");
  patch("execFile", "child_process.execFile");
  patch("execFileSync", "child_process.execFileSync");
  patch("fork", "child_process.fork");
}

function patchDns() {
  const patch = (name) => {
    const original = realDns[name];
    if (typeof original !== "function") return;
    const op = \`dns.\${String(name)}\`;
    const wrapped = wrapAsync("dns", op, original, (...args) => ({ host: typeof args[0] === "string" ? truncateString(args[0], 300) : void 0, ...baseArgs(args) }));
    tryPatch(dns, name, wrapped);
  };
  patch("lookup");
  for (const key of Object.keys(realDns)) {
    if (!key.startsWith("resolve")) continue;
    patch(key);
  }
}

function patchNet() {
  const patch = (name, op) => {
    const original = realNet[name];
    if (typeof original !== "function") return;
    const wrapped = wrapSync("net", op, original, (...args) => {
      const a0 = args[0];
      let host, port;
      if (typeof a0 === "object" && a0) {
        host = typeof a0.host === "string" ? truncateString(a0.host, 300) : void 0;
        port = typeof a0.port === "number" ? a0.port : void 0;
      }
      return { host, port, ...baseArgs(args) };
    });
    tryPatch(net, name, wrapped);
  };
  patch("connect", "net.connect");
  patch("createConnection", "net.createConnection");
}

function patchHttp(mod, modName) {
  const patch = (name) => {
    const original = mod[name];
    if (typeof original !== "function") return;
    const op = \`\${modName}.\${name}\`;
    const wrapped = wrapSync("net", op, original, (...args) => {
      const a0 = args[0];
      let host, hostname, href, method;
      if (typeof a0 === "string") href = truncateString(a0, 500);
      else if (a0 instanceof URL) href = truncateString(a0.toString(), 500);
      else if (typeof a0 === "object" && a0) {
        host = typeof a0.host === "string" ? truncateString(a0.host, 300) : void 0;
        hostname = typeof a0.hostname === "string" ? truncateString(a0.hostname, 300) : void 0;
        method = typeof a0.method === "string" ? truncateString(a0.method, 20) : void 0;
      }
      return { host, hostname, href, method, ...baseArgs(args) };
    });
    tryPatch(mod, name, wrapped);
  };
  patch("request");
  patch("get");
}

function recordStartup() {
  writeLine(JSON.stringify({
    ts: Date.now(),
    session: SESSION,
    pid: process.pid,
    ppid: typeof process.ppid === "number" ? process.ppid : -1,
    pkg: "<malwatch>",
    op: "startup",
    category: "tamper",
    args: { logFile: logFilePath, filter: FILTER, hardening: HARDENING },
    result: "ok"
  }));
}

function detectTampering() {
  if (HARDENING !== "detect") return;
  const inferredPkg = inferPackageFromStack(new Error("stack").stack);
  const checks = [
    { obj: fs, key: "writeFileSync", op: "fs.writeFileSync" },
    { obj: childProcess, key: "spawn", op: "child_process.spawn" },
    { obj: http, key: "request", op: "http.request" },
    { obj: dns, key: "lookup", op: "dns.lookup" }
  ];
  for (const c of checks) {
    const fn = c.obj?.[c.key];
    const mark = fn?.__npm_malwatch_wrapped__;
    if (!mark) {
      logEvent({ pkg: inferredPkg, op: "tamper", category: "tamper", args: { target: c.op, reason: "wrapper_missing" }, result: "ok" });
    }
  }
}

try {
  recordStartup();
  patchFs();
  patchChildProcess();
  patchDns();
  patchNet();
  patchHttp(http, "http");
  patchHttp(https, "https");
  setImmediate(detectTampering);
  process.on("beforeExit", detectTampering);
  process.on("exit", detectTampering);
} catch (e) {
  try {
    writeLine(JSON.stringify({
      ts: Date.now(),
      session: SESSION,
      pid: process.pid,
      ppid: typeof process.ppid === "number" ? process.ppid : -1,
      pkg: "<malwatch>",
      op: "preload_error",
      category: "tamper",
      args: { message: truncateString(safeToString(e?.message), 500) },
      result: "error",
      error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) }
    }));
  } catch {}
}
`;
