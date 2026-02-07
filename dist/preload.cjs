"use strict";

// Runs inside the target Node.js process via --require.
const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const childProcess = require("node:child_process");

const {
  inferPackageFromStack,
  redactObject,
  safeToString,
  shortenStack,
  truncateString
} = require("./internal.cjs");

const SESSION = process.env.NPM_MALWATCH_SESSION || `${Date.now()}-${process.pid}`;
const LOG_FILE = process.env.NPM_MALWATCH_LOG;
const FILTER = process.env.NPM_MALWATCH_FILTER || "package-only";
const INCLUDE_PM = process.env.NPM_MALWATCH_INCLUDE_PM === "1";
const HARDENING = process.env.NPM_MALWATCH_HARDENING || "detect";

const STACK_LINES = 12;
const STACK_CHARS = 2000;

const DEFAULT_LOG_DIR = path.join(process.cwd(), ".npm-malwatch");
const DEFAULT_LOG_FILE = path.join(DEFAULT_LOG_DIR, `${Date.now()}-${process.pid}.jsonl`);

const logFilePath = LOG_FILE || DEFAULT_LOG_FILE;

// Keep original references early.
const realFs = { ...fs };
const realDns = { ...dns };
const realNet = { ...net };
const realHttp = { ...http };
const realHttps = { ...https };
const realChild = { ...childProcess };

let logFd = null;

function ensureLogFd() {
  if (logFd !== null) return logFd;
  try {
    realFs.mkdirSync(path.dirname(logFilePath), { recursive: true });
  } catch {
    // ignore
  }
  logFd = realFs.openSync(logFilePath, "a");
  return logFd;
}

function writeLine(line) {
  const fd = ensureLogFd();
  try {
    realFs.writeSync(fd, line + "\n");
  } catch {
    // ignore
  }
}

function shouldEmitForPackage(pkg) {
  if (INCLUDE_PM) return true;
  if (pkg.startsWith("<pm:")) return false;
  return true;
}

function shouldEmitEvent(pkg) {
  if (FILTER !== "package-only") return true;
  if (pkg === "<unknown>") return false;
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

function baseArgs(args) {
  return { argv: redactObject(args) };
}

function wrapSync(category, op, original, makeArgs = (...args) => baseArgs(args)) {
  const wrapped = function (...args) {
    const stack = new Error("stack").stack;
    const pkg = inferPackageFromStack(stack);
    const evBase = { pkg, op, category, args: makeArgs(...args) };
    try {
      const result = original.apply(this, args);
      logEvent({ ...evBase, result: "ok", stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
      return result;
    } catch (e) {
      logEvent({
        ...evBase,
        result: "error",
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
      });
      throw e;
    }
  };
  wrapped.__npm_malwatch_wrapped__ = { category, op };
  return wrapped;
}

function wrapAsync(category, op, original, makeArgs = (...args) => baseArgs(args)) {
  const wrapped = function (...args) {
    const stack = new Error("stack").stack;
    const pkg = inferPackageFromStack(stack);
    const evBase = { pkg, op, category, args: makeArgs(...args) };
    try {
      const result = original.apply(this, args);
      if (result && typeof result.then === "function") {
        return result
          .then((v) => {
            logEvent({ ...evBase, result: "ok", stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
            return v;
          })
          .catch((e) => {
            logEvent({
              ...evBase,
              result: "error",
              error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
              stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
            });
            throw e;
          });
      }
      logEvent({ ...evBase, result: "ok", stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
      return result;
    } catch (e) {
      logEvent({
        ...evBase,
        result: "error",
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
      });
      throw e;
    }
  };
  wrapped.__npm_malwatch_wrapped__ = { category, op };
  return wrapped;
}

function tryPatch(obj, key, value) {
  try {
    obj[key] = value;
  } catch {
    // ignore
  }
}

function patchFs() {
  const wrapFs = (name, kind) => {
    const original = realFs[name];
    if (typeof original !== "function") return;
    const op = `fs.${String(name)}`;
    const makeArgs = (...args) => {
      const first = args[0];
      const p = typeof first === "string" ? first : void 0;
      return { path: p ? truncateString(p, 500) : void 0, ...baseArgs(args) };
    };
    const wrapped = kind === "sync" ? wrapSync("fs", op, original, makeArgs) : wrapAsync("fs", op, original, makeArgs);
    tryPatch(fs, name, wrapped);
  };

  const syncFns = [
    "readFileSync",
    "writeFileSync",
    "appendFileSync",
    "readdirSync",
    "statSync",
    "lstatSync",
    "readlinkSync",
    "realpathSync",
    "openSync",
    "closeSync",
    "chmodSync",
    "chownSync",
    "unlinkSync",
    "mkdirSync",
    "rmdirSync",
    "rmSync",
    "renameSync",
    "copyFileSync"
  ];
  for (const fn of syncFns) wrapFs(fn, "sync");

  const asyncFns = [
    "readFile",
    "writeFile",
    "appendFile",
    "readdir",
    "stat",
    "lstat",
    "readlink",
    "realpath",
    "open",
    "close",
    "chmod",
    "chown",
    "unlink",
    "mkdir",
    "rmdir",
    "rm",
    "rename",
    "copyFile"
  ];
  for (const fn of asyncFns) wrapFs(fn, "async");

  if (typeof realFs.createReadStream === "function") {
    tryPatch(
      fs,
      "createReadStream",
      wrapSync("fs", "fs.createReadStream", realFs.createReadStream, (...args) => ({
        path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0,
        ...baseArgs(args)
      }))
    );
  }
  if (typeof realFs.createWriteStream === "function") {
    tryPatch(
      fs,
      "createWriteStream",
      wrapSync("fs", "fs.createWriteStream", realFs.createWriteStream, (...args) => ({
        path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0,
        ...baseArgs(args)
      }))
    );
  }

  const p = fs.promises;
  const realP = realFs.promises;
  if (p && realP) {
    const promiseFns = [
      "readFile",
      "writeFile",
      "appendFile",
      "readdir",
      "stat",
      "lstat",
      "realpath",
      "open",
      "chmod",
      "chown",
      "unlink",
      "mkdir",
      "rm",
      "rename",
      "copyFile"
    ];
    for (const fn of promiseFns) {
      if (typeof realP[fn] !== "function") continue;
      try {
        p[fn] = wrapAsync("fs", `fs.promises.${fn}`, realP[fn].bind(realP), (...args) => ({
          path: typeof args[0] === "string" ? truncateString(args[0], 500) : void 0,
          ...baseArgs(args)
        }));
      } catch {
        // ignore
      }
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
    const op = `dns.${String(name)}`;
    const wrapped = wrapAsync("dns", op, original, (...args) => {
      const host = typeof args[0] === "string" ? truncateString(args[0], 300) : void 0;
      return { host, ...baseArgs(args) };
    });
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
      let host;
      let port;
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
    const op = `${modName}.${name}`;
    const wrapped = wrapSync("net", op, original, (...args) => {
      const a0 = args[0];
      let host;
      let hostname;
      let href;
      let method;
      if (typeof a0 === "string") {
        href = truncateString(a0, 500);
      } else if (a0 instanceof URL) {
        href = truncateString(a0.toString(), 500);
      } else if (typeof a0 === "object" && a0) {
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
  // Write even when package-only filter is enabled.
  writeLine(
    JSON.stringify({
      ts: Date.now(),
      session: SESSION,
      pid: process.pid,
      ppid: typeof process.ppid === "number" ? process.ppid : -1,
      pkg: "<malwatch>",
      op: "startup",
      category: "tamper",
      args: { logFile: logFilePath, filter: FILTER, hardening: HARDENING },
      result: "ok"
    })
  );
}

function detectTampering() {
  if (HARDENING !== "detect") return;
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
      logEvent({
        pkg: "<unknown>",
        op: "tamper",
        category: "tamper",
        args: { target: c.op, reason: "wrapper_missing" },
        result: "ok"
      });
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
} catch (e) {
  try {
    writeLine(
      JSON.stringify({
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
      })
    );
  } catch {
    // ignore
  }
}

