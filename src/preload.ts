/* eslint-disable @typescript-eslint/no-explicit-any */
// This file runs inside the target Node.js process via --require.

import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import childProcess from 'node:child_process';

import {
  inferPackageFromStack,
  redactObject,
  safeToString,
  shortenStack,
  truncateString,
  type MalwatchCategory,
  type MalwatchEvent
} from './internal';

const SESSION = process.env.NPM_MALWATCH_SESSION || `${Date.now()}-${process.pid}`;
const LOG_FILE = process.env.NPM_MALWATCH_LOG;
const FILTER = process.env.NPM_MALWATCH_FILTER || 'package-only';
const INCLUDE_PM = process.env.NPM_MALWATCH_INCLUDE_PM === '1';
const HARDENING = process.env.NPM_MALWATCH_HARDENING || 'detect';

const STACK_LINES = 12;
const STACK_CHARS = 2000;

const DEFAULT_LOG_DIR = path.join(process.cwd(), '.npm-malwatch');
const DEFAULT_LOG_FILE = path.join(DEFAULT_LOG_DIR, `${Date.now()}-${process.pid}.jsonl`);

const logFilePath = LOG_FILE || DEFAULT_LOG_FILE;

// Keep original references early.
const realFs = { ...fs } as typeof fs;
const realDns = { ...dns } as typeof dns;
const realNet = { ...net } as typeof net;
const realHttp = { ...http } as typeof http;
const realHttps = { ...https } as typeof https;
const realChild = { ...childProcess } as typeof childProcess;

let logFd: number | null = null;

function ensureLogFd(): number {
  if (logFd !== null) return logFd;

  try {
    realFs.mkdirSync(path.dirname(logFilePath), { recursive: true });
  } catch {
    // ignore
  }
  logFd = realFs.openSync(logFilePath, 'a');
  return logFd;
}

function writeLine(line: string): void {
  const fd = ensureLogFd();
  try {
    realFs.writeSync(fd, line + '\n');
  } catch {
    // ignore
  }
}

function shouldEmitForPackage(pkg: string): boolean {
  if (INCLUDE_PM) return true;
  if (pkg.startsWith('<pm:')) return false;
  return true;
}

function shouldEmitEvent(pkg: string): boolean {
  if (FILTER !== 'package-only') return true;
  if (pkg === '<unknown>') return false;
  if (pkg === '<malwatch>') return false;
  if (!shouldEmitForPackage(pkg)) return false;
  return true;
}

function logEvent(partial: Omit<MalwatchEvent, 'ts' | 'pid' | 'ppid' | 'session'>): void {
  const evt: MalwatchEvent = {
    ts: Date.now(),
    session: SESSION,
    pid: process.pid,
    ppid: typeof process.ppid === 'number' ? process.ppid : -1,
    ...partial
  };
  if (!shouldEmitEvent(evt.pkg)) return;
  writeLine(JSON.stringify(evt));
}

function baseArgs(args: any[]): Record<string, unknown> {
  return {
    argv: redactObject(args)
  };
}

function withStack<T>(fn: () => T): { value?: T; stack?: string } {
  const err = new Error('stack');
  const stack = err.stack;
  return { value: fn(), stack };
}

function wrapSync<T extends (...args: any[]) => any>(
  category: MalwatchCategory,
  op: string,
  original: T,
  makeArgs: (...args: Parameters<T>) => Record<string, unknown> = (...args) => baseArgs(args)
): T {
  const wrapped = function (this: any, ...args: any[]) {
    const stack = new Error('stack').stack;
    const pkg = inferPackageFromStack(stack);
    const evBase = {
      pkg,
      op,
      category,
      args: makeArgs(...(args as any))
    } as const;

    try {
      const result = original.apply(this, args);
      logEvent({ ...evBase, result: 'ok', stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
      return result;
    } catch (e: any) {
      logEvent({
        ...evBase,
        result: 'error',
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
      });
      throw e;
    }
  };
  (wrapped as any).__npm_malwatch_wrapped__ = { category, op };
  return wrapped as any as T;
}

function wrapAsync<T extends (...args: any[]) => any>(
  category: MalwatchCategory,
  op: string,
  original: T,
  makeArgs: (...args: Parameters<T>) => Record<string, unknown> = (...args) => baseArgs(args)
): T {
  const wrapped = function (this: any, ...args: any[]) {
    const stack = new Error('stack').stack;
    const pkg = inferPackageFromStack(stack);
    const evBase = {
      pkg,
      op,
      category,
      args: makeArgs(...(args as any))
    } as const;

    // We cannot await here (to keep signature), so attach to promise when possible.
    try {
      const result = original.apply(this, args);
      if (result && typeof result.then === 'function') {
        return result
          .then((v: any) => {
            logEvent({ ...evBase, result: 'ok', stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
            return v;
          })
          .catch((e: any) => {
            logEvent({
              ...evBase,
              result: 'error',
              error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
              stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
            });
            throw e;
          });
      }
      logEvent({ ...evBase, result: 'ok', stack: shortenStack(stack, STACK_LINES, STACK_CHARS) });
      return result;
    } catch (e: any) {
      logEvent({
        ...evBase,
        result: 'error',
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) },
        stack: shortenStack(stack, STACK_LINES, STACK_CHARS)
      });
      throw e;
    }
  };
  (wrapped as any).__npm_malwatch_wrapped__ = { category, op };
  return wrapped as any as T;
}

function tryPatch<T extends object, K extends keyof T>(obj: T, key: K, value: T[K]): void {
  try {
    (obj as any)[key] = value;
  } catch {
    // ignore
  }
}

function patchFs(): void {
  const wrapFs = (name: keyof typeof fs, kind: 'sync' | 'async' | 'promise') => {
    const original = (realFs as any)[name];
    if (typeof original !== 'function') return;
    const op = String(name).includes('promises') ? String(name) : `fs.${String(name)}`;
    const makeArgs = (...args: any[]) => {
      const first = args[0];
      const p = typeof first === 'string' ? first : undefined;
      return {
        path: p ? truncateString(p, 500) : undefined,
        ...baseArgs(args)
      };
    };
    const wrapped = kind === 'sync' ? wrapSync('fs', op, original, makeArgs) : wrapAsync('fs', op, original, makeArgs);
    tryPatch(fs as any, name as any, wrapped as any);
  };

  // Common fs methods
  const syncFns: Array<keyof typeof fs> = [
    'readFileSync',
    'writeFileSync',
    'appendFileSync',
    'readdirSync',
    'statSync',
    'lstatSync',
    'readlinkSync',
    'realpathSync',
    'openSync',
    'closeSync',
    'chmodSync',
    'chownSync',
    'unlinkSync',
    'mkdirSync',
    'rmdirSync',
    'rmSync',
    'renameSync',
    'copyFileSync'
  ];
  for (const fn of syncFns) wrapFs(fn, 'sync');

  const asyncFns: Array<keyof typeof fs> = [
    'readFile',
    'writeFile',
    'appendFile',
    'readdir',
    'stat',
    'lstat',
    'readlink',
    'realpath',
    'open',
    'close',
    'chmod',
    'chown',
    'unlink',
    'mkdir',
    'rmdir',
    'rm',
    'rename',
    'copyFile'
  ];
  for (const fn of asyncFns) wrapFs(fn, 'async');

  // streams
  if (typeof realFs.createReadStream === 'function') {
    tryPatch(
      fs,
      'createReadStream',
      wrapSync('fs', 'fs.createReadStream', realFs.createReadStream as any, (...args: any[]) => ({
        path: typeof args[0] === 'string' ? truncateString(args[0], 500) : undefined,
        ...baseArgs(args)
      })) as any
    );
  }
  if (typeof realFs.createWriteStream === 'function') {
    tryPatch(
      fs,
      'createWriteStream',
      wrapSync('fs', 'fs.createWriteStream', realFs.createWriteStream as any, (...args: any[]) => ({
        path: typeof args[0] === 'string' ? truncateString(args[0], 500) : undefined,
        ...baseArgs(args)
      })) as any
    );
  }

  // fs.promises
  const p = (fs as any).promises;
  const realP = (realFs as any).promises;
  if (p && realP) {
    const promiseFns = [
      'readFile',
      'writeFile',
      'appendFile',
      'readdir',
      'stat',
      'lstat',
      'realpath',
      'open',
      'chmod',
      'chown',
      'unlink',
      'mkdir',
      'rm',
      'rename',
      'copyFile'
    ] as const;
    for (const fn of promiseFns) {
      if (typeof realP[fn] !== 'function') continue;
      try {
        p[fn] = wrapAsync('fs', `fs.promises.${fn}`, realP[fn].bind(realP), (...args: any[]) => ({
          path: typeof args[0] === 'string' ? truncateString(args[0], 500) : undefined,
          ...baseArgs(args)
        }));
      } catch {
        // ignore
      }
    }
  }
}

function patchChildProcess(): void {
  const patch = (name: keyof typeof childProcess, op: string) => {
    const original = (realChild as any)[name];
    if (typeof original !== 'function') return;
    const makeArgs = (...args: any[]) => {
      const [a0, a1, a2] = args;
      // spawn(file, args?, options?)
      if (name === 'spawn' || name === 'spawnSync' || name === 'execFile' || name === 'execFileSync' || name === 'fork') {
        const file = typeof a0 === 'string' ? truncateString(a0, 300) : undefined;
        const argv = Array.isArray(a1) ? a1.map((x) => truncateString(safeToString(x), 200)).slice(0, 20) : undefined;
        return { file, argv, ...baseArgs(args) };
      }
      // exec(command, options?, cb?)
      const command = typeof a0 === 'string' ? truncateString(a0, 400) : undefined;
      return { command, ...baseArgs(args) };
    };
    const wrapped = wrapSync('proc', op, original, makeArgs);
    tryPatch(childProcess as any, name as any, wrapped as any);
  };

  patch('spawn', 'child_process.spawn');
  patch('spawnSync', 'child_process.spawnSync');
  patch('exec', 'child_process.exec');
  patch('execSync', 'child_process.execSync');
  patch('execFile', 'child_process.execFile');
  patch('execFileSync', 'child_process.execFileSync');
  patch('fork', 'child_process.fork');
}

function patchDns(): void {
  const patch = (name: keyof typeof dns) => {
    const original = (realDns as any)[name];
    if (typeof original !== 'function') return;
    const op = `dns.${String(name)}`;
    const wrapped = wrapAsync('dns', op, original, (...args: any[]) => {
      const host = typeof args[0] === 'string' ? truncateString(args[0], 300) : undefined;
      return { host, ...baseArgs(args) };
    });
    tryPatch(dns as any, name as any, wrapped as any);
  };

  patch('lookup');
  for (const key of Object.keys(realDns)) {
    if (!key.startsWith('resolve')) continue;
    patch(key as any);
  }
}

function patchNet(): void {
  const patch = (name: keyof typeof net, op: string) => {
    const original = (realNet as any)[name];
    if (typeof original !== 'function') return;

    const wrapped = wrapSync('net', op, original, (...args: any[]) => {
      const a0 = args[0];
      let host: string | undefined;
      let port: number | undefined;
      if (typeof a0 === 'object' && a0) {
        host = typeof a0.host === 'string' ? truncateString(a0.host, 300) : undefined;
        port = typeof a0.port === 'number' ? a0.port : undefined;
      }
      return { host, port, ...baseArgs(args) };
    });
    tryPatch(net as any, name as any, wrapped as any);
  };
  patch('connect', 'net.connect');
  patch('createConnection', 'net.createConnection');
}

function patchHttp(mod: typeof http | typeof https, modName: 'http' | 'https'): void {
  const patch = (name: 'request' | 'get') => {
    const original = (mod as any)[name];
    if (typeof original !== 'function') return;
    const op = `${modName}.${name}`;
    const wrapped = wrapSync('net', op, original, (...args: any[]) => {
      const a0 = args[0];
      let host: string | undefined;
      let hostname: string | undefined;
      let href: string | undefined;
      let method: string | undefined;
      if (typeof a0 === 'string') {
        href = truncateString(a0, 500);
      } else if (a0 instanceof URL) {
        href = truncateString(a0.toString(), 500);
      } else if (typeof a0 === 'object' && a0) {
        host = typeof (a0 as any).host === 'string' ? truncateString((a0 as any).host, 300) : undefined;
        hostname = typeof (a0 as any).hostname === 'string' ? truncateString((a0 as any).hostname, 300) : undefined;
        method = typeof (a0 as any).method === 'string' ? truncateString((a0 as any).method, 20) : undefined;
      }
      return { host, hostname, href, method, ...baseArgs(args) };
    });
    tryPatch(mod as any, name as any, wrapped as any);
  };
  patch('request');
  patch('get');
}

function recordStartup(): void {
  // Write even when package-only filter is enabled.
  writeLine(
    JSON.stringify({
      ts: Date.now(),
      session: SESSION,
      pid: process.pid,
      ppid: typeof process.ppid === 'number' ? process.ppid : -1,
      pkg: '<malwatch>',
      op: 'startup',
      category: 'tamper',
      args: {
        logFile: logFilePath,
        filter: FILTER,
        hardening: HARDENING
      },
      result: 'ok'
    })
  );
}

function detectTampering(): void {
  if (HARDENING !== 'detect') return;

  const checks: Array<{ obj: any; key: string; op: string }> = [
    { obj: fs, key: 'writeFileSync', op: 'fs.writeFileSync' },
    { obj: childProcess, key: 'spawn', op: 'child_process.spawn' },
    { obj: http, key: 'request', op: 'http.request' },
    { obj: dns, key: 'lookup', op: 'dns.lookup' }
  ];

  for (const c of checks) {
    const fn = c.obj?.[c.key];
    const mark = fn?.__npm_malwatch_wrapped__;
    if (!mark) {
      logEvent({
        pkg: '<unknown>',
        op: 'tamper',
        category: 'tamper',
        args: { target: c.op, reason: 'wrapper_missing' },
        result: 'ok'
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
  patchHttp(http, 'http');
  patchHttp(https, 'https');

  // run a few tamper checks later too
  setImmediate(detectTampering);
  process.on('beforeExit', detectTampering);
} catch (e: any) {
  // last resort: attempt to log preload failure
  try {
    writeLine(
      JSON.stringify({
        ts: Date.now(),
        session: SESSION,
        pid: process.pid,
        ppid: typeof process.ppid === 'number' ? process.ppid : -1,
        pkg: '<malwatch>',
        op: 'preload_error',
        category: 'tamper',
        args: { message: truncateString(safeToString(e?.message), 500) },
        result: 'error',
        error: { name: safeToString(e?.name), message: truncateString(safeToString(e?.message), 500) }
      })
    );
  } catch {
    // ignore
  }
}
