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

test('harden: a node under a home folder stops the script before anything is created', () => {
  const home = hardenScript({ ...base, platform: 'darwin', node: '/Users/alice/.nvm/versions/node/v24/bin/node' });
  shOk(home);
  const guard = home.indexOf('BLACKBOX_ALLOW_HOME_NODE');
  assert.ok(guard > 0 && guard < home.indexOf('dscl . -create'), 'the guard runs before the user is created');
  assert.match(home, /brew install node/);
  const system = hardenScript({ ...base, platform: 'darwin', node: '/opt/homebrew/bin/node' });
  assert.ok(!system.includes('BLACKBOX_ALLOW_HOME_NODE'), 'no guard for a system-wide node');
});

test('harden: the recorder user must be able to run node, checked before the code is copied', () => {
  for (const platform of ['darwin', 'linux']) {
    const s = hardenScript({ ...base, platform, node: '/usr/local/bin/node' });
    shOk(s);
    const check = s.indexOf('"$NODE" -e 0');
    assert.ok(check > 0, platform);
    assert.ok(check > s.search(/dscl \. -create|useradd/), 'after the user exists');
    assert.ok(check < s.indexOf('rm -rf "$CODE"'), 'before anything is installed');
  }
});

test('harden: the guard is real sh: it aborts with exit 1 on a home node and passes with the override', () => {
  const { spawnSync } = require('child_process');
  const s = hardenScript({ ...base, platform: 'linux', node: '/home/alice/.nvm/bin/node' });
  const run = (env) => spawnSync('sh', ['-c', s.replace('[ "$(id -u)" -eq 0 ]', 'true')], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });
  const blocked = run({});
  assert.equal(blocked.status, 1);
  assert.match(blocked.stderr, /cannot enter/);
  assert.match(blocked.stderr, /brew install node/);
  // with the override it gets past the guard and fails later (no ingest token in this sandbox), never at the guard
  const past = run({ BLACKBOX_ALLOW_HOME_NODE: '1' });
  assert.doesNotMatch(past.stderr, /cannot enter/);
});

test('harden: the service runs the compiled code (dist/), and the script stops early if there is none', () => {
  const { spawnSync } = require('child_process');
  for (const platform of ['linux', 'darwin']) {
    const s = hardenScript({ ...base, platform, node: '/usr/bin/node' });
    shOk(s);
    assert.match(s, /for f in dist package\.json; do cp -R/);
    assert.match(s, /\/usr\/local\/lib\/agent-blackbox\/dist\/bin\/blackbox\.js|\$\{CODE\}|dist\/bin\/blackbox\.js/);
    assert.ok(!/ bin\/blackbox\.js daemon/.test(s.replace(/dist\/bin\/blackbox\.js daemon/g, '')), 'no start from the sources');
  }
  // real sh, before any side effect: no dist/bin -> exit 1 with the remedy; with it, the next check (the ingest token) is reached instead
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-harden-pkg-'));
  const s = hardenScript({ ...base, platform: 'linux', node: '/usr/bin/node', pkgRoot: tmp, humanHome: path.join(tmp, 'nohome') });
  const run = () => spawnSync('sh', ['-c', s.replace('[ "$(id -u)" -eq 0 ]', 'true')], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  const without = run();
  assert.equal(without.status, 1);
  assert.match(without.stderr, /npm run build/);
  fs.mkdirSync(path.join(tmp, 'dist', 'bin'), { recursive: true });
  const withDist = run();
  assert.doesNotMatch(withDist.stderr, /npm run build/);
  assert.match(withDist.stderr, /no ingest token/);
});

test('hooks point at the recorder\'s root-owned code once it runs as its own user', () => {
  const { spawnSync } = require('child_process');
  const s = hardenScript({ ...base, platform: 'linux', node: '/usr/bin/node' });
  assert.match(s, /c\.recorderCode=process\.argv\[4\]/);
  assert.match(s, /"\$DATA" blackbox "\$CODE"/);
  assert.match(s, /hooks will point at \$CODE\/dist\/bin\/hook\.js/);
  assert.match(undoScript({ ...base, platform: 'linux' }), /delete c\.recorderCode/);

  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-hookroot-'));
  const claude = path.join(home, 'claude');
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ remoteDaemon: true, recorderCode: '/usr/local/lib/agent-blackbox' }));
  const env = { ...process.env, BLACKBOX_HOME: path.join(home, 'bb'), CLAUDE_CONFIG_DIR: claude };
  fs.mkdirSync(path.join(home, 'bb'), { recursive: true });
  fs.renameSync(path.join(home, 'config.json'), path.join(home, 'bb', 'config.json'));
  const root = path.join(__dirname, '..', 'dist');
  const inst = spawnSync(process.execPath, [path.join(root, 'src', 'install-cli.js'), 'install', '--telemetry-only'], { env, encoding: 'utf8' });
  assert.equal(inst.status, 0, inst.stderr);
  // hooks installed normally point at the root-owned copy
  const full = spawnSync(process.execPath, [path.join(root, 'src', 'install-cli.js'), 'install'], { env, encoding: 'utf8' });
  assert.equal(full.status, 0, full.stderr);
  const settings = JSON.parse(fs.readFileSync(path.join(claude, 'settings.json'), 'utf8'));
  const cmds = Object.values(settings.hooks).flatMap((g) => g.flatMap((x) => x.hooks.map((h) => h.command)));
  assert.ok(cmds.length > 5);
  for (const c of cmds) assert.match(c, /\/usr\/local\/lib\/agent-blackbox\/dist\/bin\/hook\.js" # agent-blackbox-hook$/);
  // and so does the block for managed settings
  const ms = spawnSync(process.execPath, [path.join(root, 'bin', 'blackbox.js'), 'managed-settings'], { env, encoding: 'utf8' });
  assert.match(ms.stdout, /\/usr\/local\/lib\/agent-blackbox\/dist\/bin\/hook\.js/);
  assert.ok(!ms.stdout.includes(path.join(__dirname, '..')), 'not the clone');
});
