#!/usr/bin/env node
'use strict';
// Claude Code command hook. Forwards the event to the daemon and prints its
// decision. Never exits non-zero: if the daemon is down, the event is spooled
// to disk (so the record has no gap) and the daemon is started in the background.
const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
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
        spawn(process.execPath, [path.join(__dirname, 'blackbox.js'), 'daemon'], {
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

  const req = http.request({
    host: '127.0.0.1', port: P.port, path: '/hook', method: 'POST', timeout: 4000,
    headers: { 'content-type': 'application/json', 'x-blackbox-token': readToken(), host: `127.0.0.1:${P.port}` },
  }, (res) => {
    const out = [];
    res.on('data', (c) => out.push(c));
    res.on('end', () => {
      if (res.statusCode !== 200) return fallback();
      let stdout;
      try { stdout = JSON.parse(Buffer.concat(out).toString('utf8')).stdout; } catch { return fallback(); }
      // The recorder is up: hand over anything queued while it was down. A
      // dedicated-user recorder cannot read this user's folder, so the hook sends it.
      drainSpool(() => done(stdout));
    });
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', fallback);
  req.end(raw);
});

function drainSpool(next) {
  let cfg = {};
  try { cfg = loadConfig(); } catch { /* defaults */ }
  if (!cfg.remoteDaemon || !fs.existsSync(P.spool)) return next();
  const work = `${P.spool}.${process.pid}.sending`;
  try { fs.renameSync(P.spool, work); } catch { return next(); }
  const events = fs.readFileSync(work, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const body = JSON.stringify({ events });
  const req = http.request({
    host: '127.0.0.1', port: P.port, path: '/spool', method: 'POST', timeout: 4000,
    headers: { 'content-type': 'application/json', 'x-blackbox-token': readToken(), host: `127.0.0.1:${P.port}` },
  }, (res) => {
    res.resume();
    res.on('end', () => {
      if (res.statusCode === 200) fs.unlinkSync(work);
      else fs.appendFileSync(P.spool, fs.readFileSync(work)), fs.unlinkSync(work);
      next();
    });
  });
  const putBack = () => { try { fs.appendFileSync(P.spool, fs.readFileSync(work)); fs.unlinkSync(work); } catch { /* keep */ } next(); };
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', putBack);
  req.end(body);
}
