const test = require('node:test');
const assert = require('node:assert/strict');

const { packageNameFromFilePath, inferPackageFromStack } = require('../dist/internal.cjs');

test('packageNameFromFilePath: scoped package', () => {
  const p = '/x/node_modules/@scope/pkg/lib/index.js:1:1';
  assert.equal(packageNameFromFilePath(p), '@scope/pkg');
});

test('packageNameFromFilePath: unscoped package', () => {
  const p = '/x/node_modules/lodash/index.js:1:1';
  assert.equal(packageNameFromFilePath(p), 'lodash');
});

test('packageNameFromFilePath: pnpm layout', () => {
  const p = '/x/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/index.js:1:1';
  assert.equal(packageNameFromFilePath(p), 'lodash');
});

test('inferPackageFromStack prefers node_modules path', () => {
  const stack = [
    'Error: stack',
    '  at Object.fn (/x/node_modules/a/index.js:1:1)',
    '  at Object.g (/x/node_modules/b/index.js:1:1)'
  ].join('\n');
  assert.equal(inferPackageFromStack(stack), 'a');
});

