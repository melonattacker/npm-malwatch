const fs = require('node:fs');
const cp = require('node:child_process');

fs.writeFileSync('npm-malwatch-fixture.tmp', 'hello');
cp.spawnSync(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' });

