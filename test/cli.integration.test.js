const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

test('cli wrapper produces log and summary', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-malwatch-cli-'));
  const logFile = path.join(tmp, 'out.jsonl');
  const fixture = path.join(__dirname, '..', 'testdata', 'fixture.js');

  const cli = path.join(__dirname, '..', 'dist', 'cli.cjs');
  const res = cp.spawnSync(process.execPath, [cli, '--log-file', logFile, '--', process.execPath, fixture], {
    encoding: 'utf8'
  });
  assert.equal(res.status, 0);
  assert.ok(fs.existsSync(logFile));
  const content = fs.readFileSync(logFile, 'utf8');
  assert.ok(content.includes('fs.writeFileSync'));
  // summary should be printed
  assert.ok((res.stdout || '').includes('npm-malwatch summary'));
});
