'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('package: every bin target exists and ships in "files"', () => {
  for (const [name, target] of Object.entries(pkg.bin)) {
    assert.ok(fs.existsSync(path.join(root, target)), `${name} -> ${target} exists`);
    assert.ok(pkg.files.some((f) => target === f || target.startsWith(f.replace(/\/$/, '') + '/')), `${target} is covered by "files"`);
  }
  assert.ok(pkg.bin['bb-verify'], 'the standalone verifier is a bin');
});

test('package: version, plugin manifest and changelog agree', () => {
  const plugin = JSON.parse(fs.readFileSync(path.join(root, '.claude-plugin', 'plugin.json'), 'utf8'));
  assert.equal(plugin.version, pkg.version);
  const log = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  assert.match(log, /^## Unreleased$/m);
});
