"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hookCommand = exports.hookScriptPath = exports.nodePath = exports.settingsPath = exports.HOOK_EVENTS = exports.stablePath = void 0;
exports.install = install;
exports.uninstall = uninstall;
exports.installedHookScripts = installedHookScripts;
// Wire agent-blackbox into Claude Code's user settings (~/.claude/settings.json).
const fs = require("fs");
const path = require("path");
const paths_1 = require("./paths");
const util_1 = require("./util");
Object.defineProperty(exports, "stablePath", { enumerable: true, get: function () { return util_1.stablePath; } });
exports.HOOK_EVENTS = [
    'SessionStart', 'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
    'PermissionDenied', 'SubagentStart', 'SubagentStop', 'Stop', 'StopFailure',
    'PreCompact', 'Notification', 'SessionEnd',
];
const settingsPath = () => path.join((0, util_1.claudeDir)(), 'settings.json');
exports.settingsPath = settingsPath;
const hookScript = (0, util_1.stablePath)(path.resolve(__dirname, '..', 'bin', 'hook.js'));
const nodePath = () => (0, util_1.stablePath)(process.execPath);
exports.nodePath = nodePath;
// With the recorder as its own user, the hook script is the root-owned copy it runs from:
// an agent running as you can edit your clone, but not that folder.
const hookScriptPath = () => { const code = (0, paths_1.loadConfig)().recorderCode; return code ? path.join(code, 'dist', 'bin', 'hook.js') : hookScript; };
exports.hookScriptPath = hookScriptPath;
const hookCommand = () => `"${(0, exports.nodePath)()}" "${(0, exports.hookScriptPath)()}" # agent-blackbox-hook`;
exports.hookCommand = hookCommand;
const isOurs = (h) => h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');
function desiredEnv({ raw, prompts }) {
    const env = {
        CLAUDE_CODE_ENABLE_TELEMETRY: '1',
        OTEL_LOGS_EXPORTER: 'otlp',
        OTEL_EXPORTER_OTLP_LOGS_PROTOCOL: 'http/json',
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `http://127.0.0.1:${paths_1.P.port}/v1/logs`,
        OTEL_EXPORTER_OTLP_LOGS_HEADERS: `x-blackbox-token=${(0, paths_1.readToken)()}`,
        OTEL_LOGS_EXPORT_INTERVAL: '2000',
        OTEL_LOG_TOOL_DETAILS: '1',
    };
    // prompt and response text is recorded only when asked for; the hooks already
    // keep the prompt, and the telemetry copy would double what is stored
    if (prompts) {
        env.OTEL_LOG_USER_PROMPTS = '1';
        env.OTEL_LOG_ASSISTANT_RESPONSES = '1';
    }
    if (raw)
        env.OTEL_LOG_RAW_API_BODIES = `file:${paths_1.P.bodies}`;
    return env;
}
// Values an earlier agent-blackbox install wrote (possibly with another port,
// token or data folder) belong to us and may be replaced.
function writtenByUs(k, v) {
    if (typeof v !== 'string')
        return false;
    if (k === 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT')
        return /^http:\/\/127\.0\.0\.1:\d+\/v1\/logs$/.test(v);
    if (k === 'OTEL_EXPORTER_OTLP_LOGS_HEADERS')
        return /^x-blackbox-token=[0-9a-f]+$/.test(v);
    if (k === 'OTEL_LOG_RAW_API_BODIES')
        return /^file:.*\/api-bodies$/.test(v);
    return false;
}
function readSettings(file) {
    if (!fs.existsSync(file))
        return {};
    const text = fs.readFileSync(file, 'utf8');
    if (!text.trim())
        return {};
    return JSON.parse(text); // throws on invalid JSON: never overwrite a file we cannot parse
}
function stripOurHooks(settings) {
    const hooks = settings.hooks || {};
    for (const ev of Object.keys(hooks)) {
        hooks[ev] = (hooks[ev] || [])
            .map((g) => ({ ...g, hooks: (g.hooks || []).filter((h) => !isOurs(h)) }))
            .filter((g) => g.hooks.length);
        if (!hooks[ev].length)
            delete hooks[ev];
    }
    if (!Object.keys(hooks).length)
        delete settings.hooks;
    else
        settings.hooks = hooks;
}
// hooks: false installs only the telemetry settings (for the plugin, which brings its own hooks)
function install({ mode, raw = false, prompts = false, force = false, hooks = true, log = console.log } = {}) {
    (0, paths_1.ensureDirs)();
    const file = (0, exports.settingsPath)();
    const settings = readSettings(file);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (fs.existsSync(file)) {
        const backup = `${file}.blackbox-backup-${Date.now()}`;
        fs.copyFileSync(file, backup);
        log(`  backup  ${backup}`);
    }
    // hooks: one command hook on every lifecycle event. The trailing shell
    // comment marks the entry as ours so uninstall finds it.
    stripOurHooks(settings);
    settings.hooks ||= {};
    const command = (0, exports.hookCommand)();
    if (hooks) {
        for (const ev of exports.HOOK_EVENTS) {
            (settings.hooks[ev] ||= []).push({ hooks: [{ type: 'command', command, timeout: 10 }] });
        }
    }
    if (!Object.keys(settings.hooks).length)
        delete settings.hooks;
    // env: native OpenTelemetry export + raw API bodies, remembering prior values
    const cfg = (0, paths_1.loadConfig)();
    if (mode)
        cfg.mode = mode;
    cfg.installed = cfg.installed || { env: {} };
    settings.env ||= {};
    const skipped = [];
    const want = desiredEnv({ raw, prompts });
    // a key we added before but no longer want (e.g. raw bodies turned off): restore it
    for (const [k, prev] of Object.entries(cfg.installed.env)) {
        if (k in want)
            continue;
        if (prev === null)
            delete settings.env[k];
        else
            settings.env[k] = prev;
        delete cfg.installed.env[k];
    }
    for (const [k, v] of Object.entries(want)) {
        const cur = settings.env[k];
        const ours = k in cfg.installed.env || writtenByUs(k, cur);
        if (cur !== undefined && cur !== v && !ours && !force) {
            skipped.push(k);
            continue;
        }
        if (!ours)
            cfg.installed.env[k] = cur === undefined ? null : cur;
        settings.env[k] = v;
    }
    cfg.installed.at = new Date().toISOString();
    cfg.installed.hooks = hooks;
    cfg.installed.settings = file;
    (0, paths_1.saveConfig)(cfg);
    fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
    log(hooks ? `  hooks   ${exports.HOOK_EVENTS.length} events → ${(0, exports.hookScriptPath)()}` : '  hooks   left to the Claude Code plugin');
    log(`  telemetry → http://127.0.0.1:${paths_1.P.port}/v1/logs${prompts ? ' + prompt and response text' : ''}${raw ? ' + raw API bodies (scrubbed)' : ''}`);
    if (skipped.length)
        log(`  kept your existing values for: ${skipped.join(', ')} (rerun with --force to override)`);
    return { file, skipped };
}
function uninstall({ log = console.log } = {}) {
    const file = (0, exports.settingsPath)();
    const settings = readSettings(file);
    const cfg = (0, paths_1.loadConfig)();
    stripOurHooks(settings);
    const env = settings.env || {};
    for (const [k, prev] of Object.entries((cfg.installed && cfg.installed.env) || {})) {
        if (prev === null)
            delete env[k];
        else
            env[k] = prev;
    }
    if (settings.env && !Object.keys(settings.env).length)
        delete settings.env;
    fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
    delete cfg.installed;
    (0, paths_1.saveConfig)(cfg);
    log(`  removed agent-blackbox hooks and telemetry settings from ${file}`);
    log(`  evidence kept in ${paths_1.P.home}`);
}
/** Hook scripts the installed hooks run, as written in settings.json. */
function installedHookScripts() {
    const out = new Set();
    for (const groups of Object.values(readSettings((0, exports.settingsPath)()).hooks || {})) {
        for (const g of groups)
            for (const h of g.hooks || []) {
                const m = isOurs(h) && /^"[^"]*" "([^"]+)"/.exec(h.command);
                if (m)
                    out.add(m[1]);
            }
    }
    return [...out];
}
