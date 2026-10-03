'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { checkHooks } = require('../src/integrity');

const EVENTS = ['SessionStart', 'PreToolUse', 'PostToolUse'];
const cmd = '"/usr/bin/node" "/x/bin/hook.js" # agent-blackbox-hook';

function dirWith(settings) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-int-'));
  fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify(settings));
  return dir;
}
const full = () => ({ hooks: Object.fromEntries(EVENTS.map((e) => [e, [{ hooks: [{ type: 'command', command: cmd }] }]])) });
const opts = (dir, extra = {}) => ({ expected: EVENTS, dir, managedPath: path.join(dir, 'none.json'), ...extra });

test('integrity: intact settings install passes', () => {
  const r = checkHooks(opts(dirWith(full())));
  assert.ok(r.ok, r.problems.join());
  assert.equal(r.via, 'settings');
});

test('integrity: a removed hook, disableAllHooks, a disabled plugin and a full removal are reported', () => {
  const s = full(); delete s.hooks.PreToolUse;
  let r = checkHooks(opts(dirWith(s), { installedVia: 'settings' }));
  assert.match(r.problems.join(), /removed from settings\.json for: PreToolUse/);

  r = checkHooks(opts(dirWith({ ...full(), disableAllHooks: true })));
  assert.match(r.problems.join(), /disableAllHooks/);

  r = checkHooks(opts(dirWith({ enabledPlugins: { 'agent-blackbox@agent-blackbox': false } }), { wasVia: 'plugin' }));
  assert.match(r.problems.join(), /plugin is disabled/);

  r = checkHooks(opts(dirWith({}), { wasVia: 'plugin' }));
  assert.match(r.problems.join(), /were removed/);
});

test('integrity: the fingerprint changes only when something that matters changes', () => {
  const a = checkHooks(opts(dirWith({ ...full(), theme: 'dark' })));
  const b = checkHooks(opts(dirWith({ ...full(), theme: 'light', model: 'x' })));
  const c = checkHooks(opts(dirWith({ ...full(), disableAllHooks: true })));
  assert.equal(a.fingerprint, b.fingerprint);
  assert.notEqual(a.fingerprint, c.fingerprint);
});
