#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function copy(src, dst) {
  write(dst, read(src));
}

function banner() {
  return '#!/usr/bin/env node\n';
}

function build() {
  const root = path.resolve(__dirname, '..');
  const dist = path.join(root, 'dist');
  fs.mkdirSync(dist, { recursive: true });

  // For now, this is a lightweight build step that copies the prebuilt dist.
  // The repository is intentionally self-contained for offline environments.
  const expected = ['cli.cjs', 'preload.cjs', 'summary.cjs', 'internal.cjs', 'preflight.cjs'];
  for (const f of expected) {
    const fp = path.join(dist, f);
    if (!fs.existsSync(fp)) {
      console.error(`Missing ${fp}. This repo should include dist outputs.`);
      process.exit(1);
    }
  }

  // Ensure executability hint on cli/preload via shebang line.
  const cliPath = path.join(dist, 'cli.cjs');
  const cli = read(cliPath);
  if (!cli.startsWith('#!')) {
    write(cliPath, banner() + cli);
  }
}

build();
