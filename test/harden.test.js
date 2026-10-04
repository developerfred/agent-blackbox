'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { hardenScript, undoScript, checkHardened } = require('../dist/src/harden');

const base = { node: '/usr/bin/node', human: 'alice', humanHome: '/home/alice/.blackbox', pkgRoot: '/opt/pkg', port: 7071 };

function shOk(text) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bb-harden-')), 's.sh');
  fs.writeFileSync(f, text);
  const r = spawnSync('sh', ['-n', f], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
}

test('harden: the Linux script is valid sh and sets up user, root-owned code, private data and a hardened unit', () => {
  const s = hardenScript({ ...base, platform: 'linux' });
  shOk(s);
  assert.match(s, /useradd --system/);
  assert.match(s, /chown -R root:/);
  assert.match(s, /chmod 700 "\$DATA" "\$DATA\/keys"/);
  assert.match(s, /User=blackbox/);
  assert.match(s, /NoNewPrivileges=true/);
  assert.match(s, /ReadWritePaths=\/var\/lib\/agent-blackbox/);
  assert.match(s, /remoteDaemon=true/);
  assert.match(s, /hardened=true/);
  assert.ok(!/admin-token/.test(s.replace(/#.*$/gm, '')), 'the admin token is never copied anywhere');
});

test('harden: the macOS script creates a hidden user and a launchd daemon', () => {
  const s = hardenScript({ ...base, platform: 'darwin' });
  shOk(s);
  assert.match(s, /dscl \. -create \/Users\/_blackbox/);
  assert.match(s, /<key>UserName<\/key><string>_blackbox<\/string>/);
  assert.match(s, /launchctl bootstrap system/);
});

test('harden: refuses bad names, the human as recorder user, and unsupported platforms', () => {
  assert.throws(() => hardenScript({ ...base, platform: 'linux', user: 'x; rm -rf /' }), /invalid user/);
  assert.throws(() => hardenScript({ ...base, platform: 'linux', user: 'alice' }), /must differ/);
  assert.throws(() => hardenScript({ ...base, platform: 'win32' }), /not win32/);
});

test('harden: paths with quotes cannot break out of the script', () => {
  const s = hardenScript({ ...base, platform: 'linux', pkgRoot: "/opt/it's here" });
  shOk(s);
  assert.match(s, /PKG='\/opt\/it'\\''s here'/);
});

test('harden --undo is valid sh and keeps the history', () => {
  for (const platform of ['linux', 'darwin']) {
    const s = undoScript({ ...base, platform });
    shOk(s);
    assert.match(s, /kept/);
  }
});

test('harden --check: same user or hooks starting their own recorder are reported', () => {
  assert.equal(checkHardened(null).ok, false);
  assert.equal(checkHardened({ uid: 1000 }, { uid: 1000, cfg: { remoteDaemon: true } }).ok, false);
  assert.equal(checkHardened({ uid: 998 }, { uid: 1000, cfg: {} }).ok, false);
  assert.equal(checkHardened({ uid: 998 }, { uid: 1000, cfg: { remoteDaemon: true } }).ok, true);
});
