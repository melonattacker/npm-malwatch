const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

test('preload logs fs and proc events', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-malwatch-'));
  const logFile = path.join(tmp, 'out.jsonl');
  const fixture = path.join(__dirname, '..', 'testdata', 'fixture.js');

  const res = cp.spawnSync(process.execPath, ['--require', path.join(__dirname, '..', 'dist', 'preload.cjs'), fixture], {
    env: {
      ...process.env,
      NPM_MALWATCH_LOG: logFile,
      NPM_MALWATCH_SESSION: 'test',
      NPM_MALWATCH_FILTER: 'all',
      NPM_MALWATCH_INCLUDE_PM: '1'
    },
    encoding: 'utf8'
  });
  assert.equal(res.status, 0);
  const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
  assert.ok(lines.length >= 2);
  const events = lines.map((l) => JSON.parse(l));
  const ops = new Set(events.map((e) => e.op));
  assert.ok(ops.has('fs.writeFileSync'));
  assert.ok(ops.has('child_process.spawnSync'));
});

test('preflight scan (npm-style) finds scripts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-malwatch-preflight-'));
  const nm = path.join(tmp, 'node_modules');
  fs.mkdirSync(path.join(nm, 'a'), { recursive: true });
  fs.writeFileSync(
    path.join(nm, 'a', 'package.json'),
    JSON.stringify({ name: 'a', version: '1.0.0', scripts: { postinstall: 'node install.js' } })
  );

  const { scanNodeModulesForScripts } = require('../dist/preflight.cjs');
  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ['preinstall', 'install', 'postinstall', 'prepare']
  });
  assert.equal(report.packagesWithScripts, 1);
  assert.equal(report.packages[0].name, 'a');
  assert.equal(report.packages[0].scripts.postinstall, 'node install.js');
});

test('preflight scan (pnpm-style) finds scripts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-malwatch-preflight-pnpm-'));
  const nm = path.join(tmp, 'node_modules');
  const store = path.join(nm, '.pnpm', 'lodash@4.17.21', 'node_modules', 'lodash');
  fs.mkdirSync(store, { recursive: true });
  fs.writeFileSync(
    path.join(store, 'package.json'),
    JSON.stringify({ name: 'lodash', version: '4.17.21', scripts: { install: 'node -e ""' } })
  );

  const { scanNodeModulesForScripts } = require('../dist/preflight.cjs');
  const report = scanNodeModulesForScripts(tmp, {
    includePm: false,
    maxPackages: 20000,
    scriptKeys: ['install']
  });
  assert.equal(report.packagesWithScripts, 1);
  assert.equal(report.packages[0].name, 'lodash');
  assert.ok(report.packages[0].scripts.install);
});
