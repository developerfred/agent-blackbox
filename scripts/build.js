'use strict';
// Compiles src/, bin/ and eval/ (.js and .ts) into dist/ and copies the
// assets the runtime reads next to the code. dist/ is committed, so the Claude
// Code plugin, the Homebrew formula and `npx` run without a build step; CI
// fails when it is stale (npm run build:check).
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const dist = path.join(root, 'dist');
const check = process.argv.includes('--check');

fs.rmSync(dist, { recursive: true, force: true });
execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', path.join(root, 'tsconfig.build.json')], { cwd: root, stdio: 'inherit' });
fs.copyFileSync(path.join(root, 'src', 'ui.html'), path.join(dist, 'src', 'ui.html'));
for (const f of fs.readdirSync(path.join(dist, 'bin'))) fs.chmodSync(path.join(dist, 'bin', f), 0o755);

if (check) {
  const out = execFileSync('git', ['status', '--porcelain', '--', 'dist'], { cwd: root }).toString();
  if (out.trim()) {
    console.error('dist/ is out of date; run `npm run build` and commit the result:\n' + out);
    process.exit(1);
  }
}
