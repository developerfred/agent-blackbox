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
    try {
      const log = fs.openSync(P.log, 'a');
      spawn(process.execPath, [path.join(__dirname, 'blackbox.js'), 'daemon'], {
        detached: true, stdio: ['ignore', log, log],
      }).unref();
    } catch { /* ignore */ }
    let cfg = {};
    try { cfg = loadConfig(); } catch { /* defaults */ }
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
      try { done(JSON.parse(Buffer.concat(out).toString('utf8')).stdout); } catch { fallback(); }
    });
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', fallback);
  req.end(raw);
});
