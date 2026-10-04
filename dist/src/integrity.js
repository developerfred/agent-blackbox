'use strict';
// Is agent-blackbox still wired into Claude Code? The hooks live in files the
// agent can edit, so the daemon checks them itself (on start, on every session
// start and once a minute) and records any change in the signed ledger. It
// cannot stop a determined edit; it makes one visible. Managed settings
// (`blackbox managed-settings`) are the way to make the hooks admin-owned.
const fs = require('fs');
const { claudeDir } = require('./util');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const PLUGIN_ID = 'agent-blackbox@agent-blackbox';
function managedSettingsPath() {
    if (process.platform === 'darwin')
        return '/Library/Application Support/ClaudeCode/managed-settings.json';
    if (process.platform === 'win32')
        return 'C:\\Program Files\\ClaudeCode\\managed-settings.json';
    return '/etc/claude-code/managed-settings.json';
}
/** @returns {{ exists: boolean, data: any, error?: string | null }} */
function readJson(/** @type {string} */ file) {
    try {
        return { exists: true, data: JSON.parse(fs.readFileSync(file, 'utf8') || '{}') };
    }
    catch (e) {
        return { exists: fs.existsSync(file), data: null, error: /** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT' ? null : 'unreadable or invalid JSON' };
    }
}
/** @param {any} h */
const ours = (h) => h && typeof h.command === 'string' && (h.command.includes('agent-blackbox-hook') || /agent-blackbox.*hook\.js/.test(h.command));
/** @param {any} settings @returns {Set<string>} */
function eventsWithOurHook(settings) {
    const out = new Set();
    for (const [ev, groups] of Object.entries((settings && settings.hooks) || {})) {
        for (const g of /** @type {any[]} */ (groups) || [])
            if ((g.hooks || []).some(ours))
                out.add(ev);
    }
    return out;
}
// expected: list of hook events; installed: 'settings' | 'plugin' | null (auto)
// installedVia forces the expected install kind; wasVia is the kind seen last time.
/**
 * @param {{ expected: string[], installedVia?: string | null, wasVia?: string | null, dir?: string, managedPath?: string }} opts
 */
function checkHooks({ expected, installedVia = null, wasVia = null, dir = claudeDir(), managedPath = managedSettingsPath() }) {
    const user = readJson(path.join(dir, 'settings.json'));
    const local = readJson(path.join(dir, 'settings.local.json'));
    const managed = readJson(managedPath);
    const s = user.data || {};
    const problems = [];
    const viaSettings = eventsWithOurHook(s);
    const viaManaged = eventsWithOurHook(managed.data);
    const pluginOn = !!(s.enabledPlugins && PLUGIN_ID in s.enabledPlugins); // listed, enabled or not
    const via = installedVia || (viaManaged.size ? 'managed' : viaSettings.size ? 'settings' : pluginOn ? 'plugin' : null);
    if (user.error)
        problems.push(`~/.claude/settings.json is ${user.error}`);
    for (const [name, f] of [['settings.json', s], ['settings.local.json', local.data || {}]]) {
        if (f.disableAllHooks === true)
            problems.push(`${name} sets disableAllHooks: true`);
    }
    if (via === 'settings') {
        const missing = expected.filter((e) => !viaSettings.has(e));
        if (missing.length)
            problems.push(`hooks removed from settings.json for: ${missing.join(', ')}`);
    }
    else if (via === 'plugin') {
        if (s.enabledPlugins && s.enabledPlugins[PLUGIN_ID] === false)
            problems.push('the agent-blackbox plugin is disabled');
    }
    else if (via === 'managed') {
        const missing = expected.filter((e) => !viaManaged.has(e));
        if (missing.length)
            problems.push(`hooks missing from managed settings for: ${missing.join(', ')}`);
    }
    else if (wasVia) {
        problems.push(`agent-blackbox hooks were removed (previously installed via ${wasVia})`);
    }
    // The fingerprint covers only what decides whether we run.
    const relevant = {
        hooks: [...viaSettings].sort(), managed: [...viaManaged].sort(), plugin: s.enabledPlugins ? s.enabledPlugins[PLUGIN_ID] ?? null : null,
        disableAll: !!s.disableAllHooks, disableAllLocal: !!(local.data && local.data.disableAllHooks),
    };
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify(relevant)).digest('hex').slice(0, 16);
    return { ok: problems.length === 0, via, problems, fingerprint, relevant };
}
// What to put in the managed settings file so the hooks are owned by an admin
// account and cannot be edited by the user (or the agent acting as the user).
/** @param {{ command: string, events: string[] }} opts */
function managedSettingsSnippet({ command, events }) {
    /** @type {Record<string, unknown>} */
    const hooks = {};
    for (const ev of events)
        hooks[ev] = [{ hooks: [{ type: 'command', command, timeout: 10 }] }];
    return { hooks };
}
module.exports = { checkHooks, managedSettingsPath, managedSettingsSnippet, PLUGIN_ID };
