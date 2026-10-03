#!/usr/bin/env node
'use strict';
// Claude Code command hook. Forwards the event to the daemon and prints its
// decision. Never exits non-zero: if the daemon is down, the event is spooled
// to disk (so the record has no gap) and the daemon is started in the background.
const fs = require('fs');
const path = require('path');
const { request } = require('../src/local-http');
const { P, readToken, loadConfig } = require('../src/paths');

// Installed both as a plugin and with `blackbox install`? Record once: the
// settings.json install wins and the plugin's copy of the hook steps aside.
if (process.argv.includes('--plugin')) {
  try {
    const os = require('os');
    const dir = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
    if (fs.readFileSync(path.join(dir, 'settings.json'), 'utf8').includes('agent-blackbox-hook')) {
      process.stdin.resume();
      process.stdin.on('end', () => process.exit(0));
      return;
    }
  } catch { /* no settings: the plugin records */ }
}

const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  const raw = Buffer.concat(chunks).toString('utf8');
  let ev = {};
  try { ev = JSON.parse(raw); } catch { process.exit(0); }

  const done = (out) => {
    if (out) process.stdout.write(JSON.stringify(out));
    process.exit(0);
  };

  const fallback = () => {
    try {
      fs.mkdirSync(P.home, { recursive: true, mode: 0o700 });
      fs.appendFileSync(P.spool, JSON.stringify({ received_at: new Date().toISOString(), payload: ev }) + '\n', { mode: 0o600 });
    } catch { /* nothing else we can do */ }
    let cfg = {};
    try { cfg = loadConfig(); } catch { /* defaults */ }
    // With the recorder running as a dedicated user, the system service
    // restarts it; this user must not start a second recorder of its own.
    if (!cfg.remoteDaemon) {
      try {
        const log = fs.openSync(P.log, 'a');
        require('child_process').spawn(process.execPath, [path.join(__dirname, 'blackbox.js'), 'daemon'], {
          detached: true, stdio: ['ignore', log, log],
        }).unref();
      } catch { /* ignore */ }
    }
    if (ev.hook_event_name === 'PreToolUse' && cfg.failMode === 'closed') {
      return done({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: '[agent-blackbox] The recorder is not running and failMode is "closed". Start it with: blackbox start',
        },
      });
    }
    done(null);
  };

  request({ port: P.port, method: 'POST', path: '/hook', token: readToken(), body: raw, timeout: 4000 }).then((res) => {
    if (res.status !== 200 || !res.body) return fallback();
    // The recorder is up: hand over anything queued while it was down. A
    // dedicated-user recorder cannot read this user's folder, so the hook sends it.
    drainSpool(() => done(res.body.stdout));
  }).catch(fallback); // a hook never exits non-zero
});

function drainSpool(next) {
  let cfg = {};
  try { cfg = loadConfig(); } catch { /* defaults */ }
  if (!cfg.remoteDaemon || !fs.existsSync(P.spool)) return next();
  const work = `${P.spool}.${process.pid}.sending`;
  try { fs.renameSync(P.spool, work); } catch { return next(); }
  const events = fs.readFileSync(work, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const putBack = () => { try { fs.appendFileSync(P.spool, fs.readFileSync(work)); fs.unlinkSync(work); } catch { /* keep */ } next(); };
  request({ port: P.port, method: 'POST', path: '/spool', token: readToken(), body: { events }, timeout: 4000 }).then((res) => {
    if (res.status !== 200) return putBack();
    fs.unlinkSync(work);
    next();
  }, putBack);
}
