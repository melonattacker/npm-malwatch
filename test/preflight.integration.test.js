const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

test('cli preflight injects --ignore-scripts for install-like commands', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-malwatch-preflight-cli-'));
  // Create a minimal node_modules with one script so preflight has output.
  const nm = path.join(tmp, 'node_modules', 'a');
  fs.mkdirSync(nm, { recursive: true });
  fs.writeFileSync(
    path.join(nm, 'package.json'),
    JSON.stringify({ name: 'a', version: '1.0.0', scripts: { postinstall: 'echo hi' } })
  );

  const out = path.join(tmp, 'report.json');
  const cli = path.join(__dirname, '..', 'dist', 'cli.cjs');

  // Use a fake "pm" command implemented as node -e.
  // It prints args so we can confirm injection.
  const res = cp.spawnSync(
    process.execPath,
    [
      cli,
      'preflight',
      '--format',
      'json',
      '--output',
      out,
      '--',
      process.execPath,
      '-e',
      'console.log(JSON.stringify(process.argv.slice(2)))',
      'install'
    ],
    { cwd: tmp, encoding: 'utf8' }
  );

  assert.equal(res.status, 0);
  const stdout = String(res.stdout || '');
  const jsonStart = stdout.indexOf('{');
  assert.ok(jsonStart >= 0);
  const report = JSON.parse(stdout.slice(jsonStart));
  assert.ok(Array.isArray(report.pmCommand));
  assert.ok(report.pmCommand.includes('--ignore-scripts'));
  assert.ok(fs.existsSync(out));
});
