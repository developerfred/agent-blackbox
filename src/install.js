'use strict';
// Wire agent-blackbox into Claude Code's user settings (~/.claude/settings.json).
const fs = require('fs');
const os = require('os');
const path = require('path');
const { P, ensureDirs, readToken, loadConfig, saveConfig } = require('./paths');
const { claudeDir } = require('./util');

const HOOK_EVENTS = [
  'SessionStart', 'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
  'PermissionDenied', 'SubagentStart', 'SubagentStop', 'Stop', 'StopFailure',
  'PreCompact', 'Notification', 'SessionEnd',
];

const settingsPath = () => path.join(claudeDir(), 'settings.json');
// Homebrew installs into versioned folders (…/Cellar/<name>/<version>/…) that
// disappear on upgrade; its stable symlinks live in …/opt/<name>/. Hooks must
// point at the stable path or they break on the next `brew upgrade`.
/** @param {string} p */
function stablePath(p) {
  const m = /^(.*)\/Cellar\/([^/]+)\/[^/]+\/(.*)$/.exec(p);
  if (!m) return p;
  const opt = path.join(m[1], 'opt', m[2], m[3]);
  return fs.existsSync(opt) ? opt : p;
}

const hookScript = stablePath(path.resolve(__dirname, '..', 'bin', 'hook.js'));
const nodePath = () => stablePath(process.execPath);
/** @param {any} h */
const isOurs = (h) => h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');

/** @param {{ raw?: boolean, prompts?: boolean }} opts @returns {Record<string, string>} */
function desiredEnv({ raw, prompts }) {
  /** @type {Record<string, string>} */
  const env = {
    CLAUDE_CODE_ENABLE_TELEMETRY: '1',
    OTEL_LOGS_EXPORTER: 'otlp',
    OTEL_EXPORTER_OTLP_LOGS_PROTOCOL: 'http/json',
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `http://127.0.0.1:${P.port}/v1/logs`,
    OTEL_EXPORTER_OTLP_LOGS_HEADERS: `x-blackbox-token=${readToken()}`,
    OTEL_LOGS_EXPORT_INTERVAL: '2000',
    OTEL_LOG_TOOL_DETAILS: '1',
  };
  // prompt and response text is recorded only when asked for; the hooks already
  // keep the prompt, and the telemetry copy would double what is stored
  if (prompts) { env.OTEL_LOG_USER_PROMPTS = '1'; env.OTEL_LOG_ASSISTANT_RESPONSES = '1'; }
  if (raw) env.OTEL_LOG_RAW_API_BODIES = `file:${P.bodies}`;
  return env;
}

// Values an earlier agent-blackbox install wrote (possibly with another port,
// token or data folder) belong to us and may be replaced.
/** @param {string} k @param {unknown} v */
function writtenByUs(k, v) {
  if (typeof v !== 'string') return false;
  if (k === 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT') return /^http:\/\/127\.0\.0\.1:\d+\/v1\/logs$/.test(v);
  if (k === 'OTEL_EXPORTER_OTLP_LOGS_HEADERS') return /^x-blackbox-token=[0-9a-f]+$/.test(v);
  if (k === 'OTEL_LOG_RAW_API_BODIES') return /^file:.*\/api-bodies$/.test(v);
  return false;
}

/** @param {string} file @returns {Record<string, any>} */
function readSettings(file) {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  return JSON.parse(text); // throws on invalid JSON: never overwrite a file we cannot parse
}

/** @param {Record<string, any>} settings */
function stripOurHooks(settings) {
  const hooks = settings.hooks || {};
  for (const ev of Object.keys(hooks)) {
    hooks[ev] = (hooks[ev] || [])
      .map((/** @type {{ hooks?: any[] }} */ g) => ({ ...g, hooks: (g.hooks || []).filter((h) => !isOurs(h)) }))
      .filter((/** @type {{ hooks: any[] }} */ g) => g.hooks.length);
    if (!hooks[ev].length) delete hooks[ev];
  }
  if (!Object.keys(hooks).length) delete settings.hooks; else settings.hooks = hooks;
}

// hooks: false installs only the telemetry settings (for the plugin, which brings its own hooks)
/** @param {{ mode?: import('./types').Mode, raw?: boolean, prompts?: boolean, force?: boolean, hooks?: boolean, log?: (msg: string) => void }} [opts] */
function install({ mode, raw = false, prompts = false, force = false, hooks = true, log = console.log } = {}) {
  ensureDirs();
  const file = settingsPath();
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
  const command = `"${nodePath()}" "${hookScript}" # agent-blackbox-hook`;
  if (hooks) {
    for (const ev of HOOK_EVENTS) {
      (settings.hooks[ev] ||= []).push({ hooks: [{ type: 'command', command, timeout: 10 }] });
    }
  }
  if (!Object.keys(settings.hooks).length) delete settings.hooks;

  // env: native OpenTelemetry export + raw API bodies, remembering prior values
  const cfg = loadConfig();
  if (mode) cfg.mode = mode;
  cfg.installed = cfg.installed || { env: {} };
  settings.env ||= {};
  const skipped = [];
  const want = desiredEnv({ raw, prompts });
  // a key we added before but no longer want (e.g. raw bodies turned off): restore it
  for (const [k, prev] of Object.entries(cfg.installed.env)) {
    if (k in want) continue;
    if (prev === null) delete settings.env[k]; else settings.env[k] = prev;
    delete cfg.installed.env[k];
  }
  for (const [k, v] of Object.entries(want)) {
    const cur = settings.env[k];
    const ours = k in cfg.installed.env || writtenByUs(k, cur);
    if (cur !== undefined && cur !== v && !ours && !force) { skipped.push(k); continue; }
    if (!ours) cfg.installed.env[k] = cur === undefined ? null : cur;
    settings.env[k] = v;
  }
  cfg.installed.at = new Date().toISOString();
  cfg.installed.hooks = hooks;
  cfg.installed.settings = file;
  saveConfig(cfg);

  fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
  log(hooks ? `  hooks   ${HOOK_EVENTS.length} events → ${hookScript}` : '  hooks   left to the Claude Code plugin');
  log(`  telemetry → http://127.0.0.1:${P.port}/v1/logs${prompts ? ' + prompt and response text' : ''}${raw ? ' + raw API bodies (scrubbed)' : ''}`);
  if (skipped.length) log(`  kept your existing values for: ${skipped.join(', ')} (rerun with --force to override)`);
  return { file, skipped };
}

function uninstall({ log = console.log } = {}) {
  const file = settingsPath();
  const settings = readSettings(file);
  const cfg = loadConfig();
  stripOurHooks(settings);
  const env = settings.env || {};
  for (const [k, prev] of Object.entries((cfg.installed && cfg.installed.env) || {})) {
    if (prev === null) delete env[k]; else env[k] = prev;
  }
  if (settings.env && !Object.keys(settings.env).length) delete settings.env;
  fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
  delete cfg.installed;
  saveConfig(cfg);
  log(`  removed agent-blackbox hooks and telemetry settings from ${file}`);
  log(`  evidence kept in ${P.home}`);
}

module.exports = { install, uninstall, settingsPath, HOOK_EVENTS, stablePath };
