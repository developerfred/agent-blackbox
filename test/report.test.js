'use strict';
// The terminal reports are pinned against output captured before they were refactored.
const test = require('node:test');
const assert = require('node:assert');
const fx = require('./fixtures/report');
const golden = require('./fixtures/report-golden.json');
const { renderMcp } = require('../dist/src/mcp-report');
const { renderSkills } = require('../dist/src/skills-report');

test('blackbox mcp report: plain, colored with --all, and ordering', () => {
  assert.equal(renderMcp(fx.mcpAudits, fx.summary, {}), golden.mcp);
  assert.equal(renderMcp(fx.mcpAudits, fx.summary, { color: true, all: true }), golden.mcpColorAll);
  assert.ok(!golden.mcp.includes('\x1b['), 'no escapes without color');
  assert.ok(golden.mcpColorAll.includes('\x1b[31m'), 'high risk is red');
});

test('blackbox skills report: sorted by risk then name, low notes behind --all', () => {
  assert.equal(renderSkills(fx.skills, {}), golden.skills);
  assert.equal(renderSkills(fx.skills, { color: true, all: true }), golden.skillsColorAll);
  assert.equal(renderSkills([], {}), golden.empty);
  const names = [...golden.skills.matchAll(/^ {2}(?:high|medium|low|clean) +(\S+)/gm)].map((m) => m[1]);
  assert.deepEqual(names, ['zeta', 'beta', 'alpha']);
});

test('cli: --mode is validated for eval and install', () => {
  const { spawnSync } = require('child_process');
  const bin = require('path').join(__dirname, '..', 'dist', 'bin', 'blackbox.js');
  const bad = spawnSync(process.execPath, [bin, 'eval', '--mode', 'bogus'], { encoding: 'utf8', env: { ...process.env, BLACKBOX_HOME: require('os').tmpdir() + '/bb-mode' } });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /mode must be ask, deny or monitor/);
  const ok = spawnSync(process.execPath, [bin, 'eval', '--mode', 'deny', '--json'], { encoding: 'utf8', env: { ...process.env, BLACKBOX_HOME: require('os').tmpdir() + '/bb-mode' } });
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(JSON.parse(ok.stdout).attacks > 0);
});

test('cli status: with the recorder as its own user it shows where the evidence really is', () => {
  const { spawnSync } = require('child_process');
  const home = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'bb-status-'));
  require('fs').writeFileSync(require('path').join(home, 'config.json'), JSON.stringify({ remoteDaemon: true, recorderHome: '/Library/Application Support/agent-blackbox', recorderUser: '_blackbox' }));
  const bin = require('path').join(__dirname, '..', 'dist', 'bin', 'blackbox.js');
  const r = spawnSync(process.execPath, [bin, 'status'], { encoding: 'utf8', env: { ...process.env, BLACKBOX_HOME: home, BLACKBOX_PORT: '39999' } });
  assert.match(r.stdout, /not running/);
  assert.match(r.stdout, /data: \/Library\/Application Support\/agent-blackbox/);
  assert.ok(!r.stdout.includes(home), 'the human folder is not presented as the data folder');
});
