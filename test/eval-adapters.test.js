'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('child_process');
const path = require('path');
const { runAgent, runCaseVia } = require('../dist/eval/run');
const { CASES } = require('../dist/eval/corpus');

for (const agent of ['codex', 'cursor', 'gemini']) {
  test(`eval via the ${agent} adapter: same catch rate and no new false alarms as in Claude Code's format`, () => {
    const r = runAgent(agent);
    assert.ok(r.applicable > 60, `only ${r.applicable} cases expressible`);
    assert.equal(r.caught, r.attacks);
    assert.equal(r.falseAlarms, 0);
    assert.deepEqual(r.diverged, [], 'translation changed a verdict');
  });
}

test('eval via adapters: what an agent has no hook for is reported, not skipped silently', () => {
  // no agent has a PowerShell tool
  for (const agent of ['codex', 'cursor', 'gemini']) assert.ok(runAgent(agent, 'ask').notApplicable.includes('powershell-iwr'), agent);
  // Cursor's edit hook runs after the write: the memory-write cases cannot be gated there
  const cursor = runAgent('cursor').notApplicable;
  for (const id of ['memory-agents-md-after-fetch', 'memory-skill-edit']) assert.ok(cursor.includes(id), id);
  // Codex and Gemini gate edits (apply_patch, write_file) before they happen
  for (const agent of ['codex', 'gemini']) assert.ok(!runAgent(agent).notApplicable.includes('memory-agents-md-after-fetch'), agent);
});

test('eval via adapters: a broken mapping is caught (the harness is not vacuous)', () => {
  const gemini = require('../dist/src/adapters/gemini');
  const real = gemini.decode;
  gemini.decode = (n) => { const ev = real(n); if (ev && ev.tool_name === 'Bash') ev.tool_name = 'Shell'; return ev; };
  try {
    const r = runAgent('gemini');
    assert.ok(r.caught < r.attacks && r.diverged.length > 0);
  } finally { gemini.decode = real; }
  const c = CASES.find((x) => x.id === 'plain-curl');
  assert.equal(runCaseVia(c, 'gemini').blocked, true);
});

test('cli: eval --agent runs the corpus through an adapter and rejects unknown agents', () => {
  const bin = path.join(__dirname, '..', 'dist', 'bin', 'blackbox.js');
  const env = { ...process.env, BLACKBOX_HOME: require('os').tmpdir() + '/bb-eval-agent' };
  const ok = spawnSync(process.execPath, [bin, 'eval', '--agent', 'codex', '--json'], { encoding: 'utf8', env });
  assert.equal(ok.status, 0, ok.stderr);
  const [r] = JSON.parse(ok.stdout);
  assert.deepEqual([r.agent, r.caught === r.attacks, r.diverged], ['codex', true, []]);
  const bad = spawnSync(process.execPath, [bin, 'eval', '--agent', 'vim'], { encoding: 'utf8', env });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /unknown agent/);
});
