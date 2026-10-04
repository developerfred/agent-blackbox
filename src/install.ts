// Wire agent-blackbox into Claude Code's user settings (~/.claude/settings.json).
import * as fs from 'fs';
import * as path from 'path';
import { P, ensureDirs, readToken, loadConfig, saveConfig } from './paths';
import { claudeDir, stablePath } from './util';
import type { Mode } from './types';

// re-exported: the CLI and the installers for other agents reach it from here
export { stablePath };

export const HOOK_EVENTS = [
  'SessionStart', 'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
  'PermissionDenied', 'SubagentStart', 'SubagentStop', 'Stop', 'StopFailure',
  'PreCompact', 'Notification', 'SessionEnd',
];

export const settingsPath = (): string => path.join(claudeDir(), 'settings.json');
const hookScript = stablePath(path.resolve(__dirname, '..', 'bin', 'hook.js'));
export const nodePath = (): string => stablePath(process.execPath);
// With the recorder as its own user, the hook script is the root-owned copy it runs from:
// an agent running as you can edit your clone, but not that folder.
export const hookScriptPath = (): string => { const code = loadConfig().recorderCode; return code ? path.join(code, 'dist', 'bin', 'hook.js') : hookScript; };
export const hookCommand = (): string => `"${nodePath()}" "${hookScriptPath()}" # agent-blackbox-hook`;
const isOurs = (h: any): boolean => h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');

function desiredEnv({ raw, prompts }: { raw?: boolean; prompts?: boolean }): Record<string, string> {
  const env: Record<string, string> = {
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
function writtenByUs(k: string, v: unknown): boolean {
  if (typeof v !== 'string') return false;
  if (k === 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT') return /^http:\/\/127\.0\.0\.1:\d+\/v1\/logs$/.test(v);
  if (k === 'OTEL_EXPORTER_OTLP_LOGS_HEADERS') return /^x-blackbox-token=[0-9a-f]+$/.test(v);
  if (k === 'OTEL_LOG_RAW_API_BODIES') return /^file:.*\/api-bodies$/.test(v);
  return false;
}

function readSettings(file: string): Record<string, any> {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  return JSON.parse(text); // throws on invalid JSON: never overwrite a file we cannot parse
}

function stripOurHooks(settings: Record<string, any>): void {
  const hooks = settings.hooks || {};
  for (const ev of Object.keys(hooks)) {
    hooks[ev] = (hooks[ev] || [])
      .map((g: { hooks?: any[] }) => ({ ...g, hooks: (g.hooks || []).filter((h) => !isOurs(h)) }))
      .filter((g: { hooks: any[] }) => g.hooks.length);
    if (!hooks[ev].length) delete hooks[ev];
  }
  if (!Object.keys(hooks).length) delete settings.hooks; else settings.hooks = hooks;
}

// hooks: false installs only the telemetry settings (for the plugin, which brings its own hooks)
export function install({ mode, raw = false, prompts = false, force = false, hooks = true, log = console.log }: { mode?: Mode; raw?: boolean; prompts?: boolean; force?: boolean; hooks?: boolean; log?: (msg: string) => void } = {}): { file: string; skipped: string[] } {
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
  const command = hookCommand();
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
  const skipped: string[] = [];
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
  log(hooks ? `  hooks   ${HOOK_EVENTS.length} events → ${hookScriptPath()}` : '  hooks   left to the Claude Code plugin');
  log(`  telemetry → http://127.0.0.1:${P.port}/v1/logs${prompts ? ' + prompt and response text' : ''}${raw ? ' + raw API bodies (scrubbed)' : ''}`);
  if (skipped.length) log(`  kept your existing values for: ${skipped.join(', ')} (rerun with --force to override)`);
  return { file, skipped };
}

export function uninstall({ log = console.log }: { log?: (msg: string) => void } = {}): void {
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

/** Hook scripts the installed hooks run, as written in settings.json. */
export function installedHookScripts(): string[] {
  const out = new Set<string>();
  for (const groups of Object.values(readSettings(settingsPath()).hooks || {})) {
    for (const g of (groups as any[])) for (const h of g.hooks || []) {
      const m = isOurs(h) && /^"[^"]*" "([^"]+)"/.exec(h.command);
      if (m) out.add(m[1]);
    }
  }
  return [...out];
}
