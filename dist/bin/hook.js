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
function pluginStepsAside() {
    if (!process.argv.includes('--plugin'))
        return false;
    try {
        return fs.readFileSync(path.join(require('../src/util').claudeDir(), 'settings.json'), 'utf8').includes('agent-blackbox-hook');
    }
    catch {
        return false; /* no settings: the plugin records */
    }
}
const shadowed = pluginStepsAside();
/** @type {Buffer[]} */
const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
    if (shadowed)
        process.exit(0);
    const raw = Buffer.concat(chunks).toString('utf8');
    /** @type {Partial<import('../src/types').HookEvent>} */
    let ev = {};
    try {
        ev = JSON.parse(raw);
    }
    catch {
        process.exit(0);
    }
    /** @param {object | null} out what Claude Code reads from the hook's stdout */
    const done = (out) => {
        if (out)
            process.stdout.write(JSON.stringify(out));
        process.exit(0);
    };
    const fallback = () => {
        try {
            fs.mkdirSync(P.home, { recursive: true, mode: 0o700 });
            fs.appendFileSync(P.spool, JSON.stringify({ received_at: new Date().toISOString(), payload: ev }) + '\n', { mode: 0o600 });
        }
        catch { /* nothing else we can do */ }
        /** @type {Partial<import('../src/types').Config>} */
        let cfg = {};
        try {
            cfg = loadConfig();
        }
        catch { /* defaults */ }
        // With the recorder running as a dedicated user, the system service
        // restarts it; this user must not start a second recorder of its own.
        if (!cfg.remoteDaemon) {
            try {
                const log = fs.openSync(P.log, 'a');
                require('child_process').spawn(process.execPath, [path.join(__dirname, 'blackbox.js'), 'daemon'], {
                    detached: true, stdio: ['ignore', log, log],
                }).unref();
            }
            catch { /* ignore */ }
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
        if (res.status !== 200 || !res.body)
            return fallback();
        // The recorder is up: hand over anything queued while it was down. A
        // dedicated-user recorder cannot read this user's folder, so the hook sends it.
        drainSpool(() => done(res.body.stdout));
    }).catch(fallback); // a hook never exits non-zero
});
/** @param {() => void} next */
function drainSpool(next) {
    /** @type {Partial<import('../src/types').Config>} */
    let cfg = {};
    try {
        cfg = loadConfig();
    }
    catch { /* defaults */ }
    if (!cfg.remoteDaemon || !fs.existsSync(P.spool))
        return next();
    const work = `${P.spool}.${process.pid}.sending`;
    try {
        fs.renameSync(P.spool, work);
    }
    catch {
        return next();
    }
    const events = require('../src/util').readJsonl(work);
    const putBack = () => { try {
        fs.appendFileSync(P.spool, fs.readFileSync(work));
        fs.unlinkSync(work);
    }
    catch { /* keep */ } next(); };
    request({ port: P.port, method: 'POST', path: '/spool', token: readToken(), body: { events }, timeout: 4000 }).then((res) => {
        if (res.status !== 200)
            return putBack();
        fs.unlinkSync(work);
        next();
    }, putBack);
}
