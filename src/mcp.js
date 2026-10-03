'use strict';
// MCP servers: where they are configured (for every agent on this machine),
// how they run, what the agent actually did with them, and what in their
// configuration is risky. Read-only; secret values are never printed.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { redact } = require('./policy');

const SEV = { high: 3, medium: 2, low: 1, info: 0, none: -1 };
// Tool-name verbs that send data somewhere or change state.
const OUTBOUND = /(send|post|create|write|upload|publish|email|mail|message|comment|reply|push|share|invite|update|delete|remove|merge|deploy|execute|exec|run|bash|shell|insert|transfer|pay|commit|stage|move|rename|grant|approve|kill|set_|batch|request_\w*access)/i;
const SECRET_VALUE = [/\bAKIA[0-9A-Z]{16}\b/, /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/, /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/, /\bgh[pousr]_[A-Za-z0-9]{30,}/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}/, /\bxox[abpr]-[A-Za-z0-9-]{10,}/, /\bAIza[0-9A-Za-z_-]{35}\b/, /\bglpat-[A-Za-z0-9_-]{20,}/, /\bnpm_[A-Za-z0-9]{36}\b/];
const SECRET_KEY = /(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE|CREDENTIAL|AUTH)/i;

const { readJson, sha256 } = require('./util');
const exists = (f) => { try { fs.accessSync(f); return true; } catch { return false; } };

// Tiny TOML reader for Codex's [mcp_servers.<name>] tables.
function codexServers(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return {}; }
  const out = {};
  let cur = null, sub = null;
  const val = (v) => {
    v = v.trim();
    if (v.startsWith('[')) return [...v.matchAll(/"((?:\\.|[^"\\])*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2]);
    const m = /^"((?:\\.|[^"\\])*)"|^'([^']*)'/.exec(v);
    return m ? (m[1] ?? m[2]) : v.replace(/\s+#.*$/, '');
  };
  for (const line of text.split(/\r?\n/)) {
    const t = /^\s*\[\s*mcp_servers\.("?)([^".\]]+)\1(?:\.(\w+))?\s*\]\s*$/.exec(line);
    if (t) { cur = (out[t[2]] ||= {}); sub = t[3] || null; if (sub) cur[sub] ||= {}; continue; }
    if (/^\s*\[/.test(line)) { cur = null; continue; }
    const kv = /^\s*([\w-]+)\s*=\s*(.+)$/.exec(line);
    if (cur && kv) (sub ? cur[sub] : cur)[kv[1]] = val(kv[2]);
  }
  return out;
}

function candidateConfigs(home = os.homedir(), cwd = process.cwd()) {
  const claudeJson = process.env.CLAUDE_CONFIG_DIR ? path.join(process.env.CLAUDE_CONFIG_DIR, '.claude.json') : path.join(home, '.claude.json');
  const lib = path.join(home, 'Library', 'Application Support');
  return [
    { client: 'Claude Code', scope: 'user', file: claudeJson, pick: (j) => j.mcpServers },
    { client: 'Claude Code', scope: 'local', file: claudeJson, pick: (j) => (j.projects && j.projects[cwd] && j.projects[cwd].mcpServers) },
    { client: 'Claude Code', scope: 'project', file: path.join(cwd, '.mcp.json'), pick: (j) => j.mcpServers },
    { client: 'Claude Desktop', scope: 'user', file: path.join(lib, 'Claude', 'claude_desktop_config.json'), pick: (j) => j.mcpServers },
    { client: 'Claude Desktop', scope: 'user', file: path.join(home, '.config', 'Claude', 'claude_desktop_config.json'), pick: (j) => j.mcpServers },
    { client: 'Cursor', scope: 'user', file: path.join(home, '.cursor', 'mcp.json'), pick: (j) => j.mcpServers },
    { client: 'Cursor', scope: 'project', file: path.join(cwd, '.cursor', 'mcp.json'), pick: (j) => j.mcpServers },
    { client: 'Codex', scope: 'user', file: path.join(home, '.codex', 'config.toml'), toml: true },
    { client: 'Gemini CLI', scope: 'user', file: path.join(home, '.gemini', 'settings.json'), pick: (j) => j.mcpServers },
    { client: 'Gemini CLI', scope: 'project', file: path.join(cwd, '.gemini', 'settings.json'), pick: (j) => j.mcpServers },
    { client: 'VS Code', scope: 'project', file: path.join(cwd, '.vscode', 'mcp.json'), pick: (j) => j.servers || j.mcpServers },
    { client: 'Windsurf', scope: 'user', file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), pick: (j) => j.mcpServers },
    { client: 'Copilot CLI', scope: 'user', file: path.join(home, '.copilot', 'mcp-config.json'), pick: (j) => j.mcpServers },
  ];
}

// Plugin-provided servers: <plugin>/.mcp.json or plugin.json "mcpServers".
function pluginConfigs(home) {
  const root = path.join(process.env.CLAUDE_CONFIG_DIR || path.join(home, '.claude'), 'plugins');
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory() && e.name !== 'node_modules' && e.name !== '.git') walk(p, depth + 1);
      else if (e.name === '.mcp.json') out.push({ client: 'Claude Code', scope: 'plugin', plugin: path.basename(path.dirname(p)), file: p, pick: (j) => j.mcpServers || j });
      else if (e.name === 'plugin.json') out.push({ client: 'Claude Code', scope: 'plugin', plugin: path.basename(path.dirname(path.dirname(p))), file: p, pick: (j) => j.mcpServers });
    }
  };
  walk(root, 0);
  return out;
}

function discoverServers({ home = os.homedir(), cwd = process.cwd() } = {}) {
  const servers = [];
  for (const c of [...candidateConfigs(home, cwd), ...pluginConfigs(home)]) {
    if (!exists(c.file)) continue;
    let map = null;
    if (c.toml) map = codexServers(c.file);
    else { const j = readJson(c.file); map = j && c.pick(j); }
    if (!map || typeof map !== 'object') continue;
    for (const [name, def] of Object.entries(map)) {
      if (!def || typeof def !== 'object') continue;
      const transport = def.type || def.transport || (def.url || def.serverUrl || def.httpUrl ? 'http' : 'stdio');
      servers.push({
        name, client: c.client, scope: c.scope, plugin: c.plugin, file: c.file, transport,
        command: typeof def.command === 'string' ? def.command : null,
        args: Array.isArray(def.args) ? def.args.map(String) : [],
        url: def.url || def.serverUrl || def.httpUrl || null,
        env: def.env && typeof def.env === 'object' ? def.env : {},
        headers: def.headers && typeof def.headers === 'object' ? def.headers : {},
        disabled: def.disabled === true || def.enabled === false,
      });
    }
  }
  return servers;
}

// ---------- audit ----------

const isRef = (v) => /^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$|^env:|^\{env:/.test(String(v).trim());
const mask = (v) => { const s = String(v); return s.length <= 8 ? '•••' : s.slice(0, 4) + '…' + `(${s.length} chars)`; };

function auditServer(s, { home: homeDir = os.homedir() } = {}) {
  const f = [];
  const add = (severity, rule, message, detail) => f.push({ severity, rule, message, detail: detail ? redact(detail) : null });
  // literal secrets in env or headers
  for (const [where, obj] of [['env', s.env], ['headers', s.headers]]) {
    for (const [k, v] of Object.entries(obj || {})) {
      const val = String(v);
      if (!val || isRef(val)) continue;
      const looksSecret = SECRET_VALUE.some((re) => re.test(val)) || (SECRET_KEY.test(k) && val.replace(/^Bearer\s+/i, '').length >= 12 && !/\$\{/.test(val));
      if (looksSecret) add('high', 'plaintext-secret', `${where}.${k} holds a credential in clear text in ${path.basename(s.file)}; use an environment variable reference instead`, `${k}=${mask(val.replace(/^Bearer\s+/i, ''))}`);
    }
  }
  const argv = [s.command, ...s.args].filter(Boolean).join(' ');
  for (const a of s.args) if (SECRET_VALUE.some((re) => re.test(a))) add('high', 'plaintext-secret', 'a command-line argument contains a credential (visible to every process on the machine)', mask(a));
  // packages fetched at launch without a pinned version
  const runner = /(^|\/)(npx|bunx|uvx|pipx)$/.test(s.command || '') || (/(^|\/)(pnpm|yarn)$/.test(s.command || '') && /\b(dlx)\b/.test(s.args.join(' ')));
  if (runner) {
    const pkg = s.args.find((a) => !a.startsWith('-') && a !== 'dlx' && a !== 'run');
    if (pkg) {
      const pinned = /^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+/.test(pkg) || /==\d/.test(pkg);
      if (!pinned) add('medium', 'unpinned-package', `downloads and runs "${pkg.replace(/@latest$/, '')}" at its latest version on every start: a compromised release would run with your permissions`, `${s.command} ${s.args.join(' ')}`);
    }
  }
  if (s.url) {
    let u = null;
    try { u = new URL(String(s.url).replace(/\$\{[^}]+\}/g, 'x')); } catch { /* templated */ }
    if (u && u.protocol === 'http:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)) add('high', 'insecure-transport', `talks to ${u.hostname} over plain HTTP: tokens and data travel unencrypted`, null);
    if (u && /[?&](key|token|api_key|apikey|access_token)=/i.test(u.search)) add('high', 'secret-in-url', 'the server URL carries a credential in its query string', null);
  }
  if (/(^|\/)(sh|bash|zsh|cmd|powershell|pwsh)$/.test(s.command || '') && s.args.some((a) => a === '-c' || a === '/c' || a === '-Command')) {
    add('medium', 'shell-wrapper', 'starts through a shell command string, which hides what actually runs', argv.slice(0, 160));
  }
  if (/(^|\/)docker$/.test(s.command || '')) {
    if (s.args.includes('--privileged')) add('high', 'docker-privileged', 'runs a privileged container (full access to the host)', null);
    if (s.args.some((a) => /docker\.sock/.test(a))) add('high', 'docker-socket', 'mounts the Docker socket (equivalent to root on the host)', null);
    if (s.args.some((a, i) => (s.args[i - 1] === '-v' || s.args[i - 1] === '--volume') && /^(\/|~|\$HOME)(:|$)/.test(a))) add('high', 'docker-host-mount', 'mounts the whole filesystem or home folder into the container', null);
    if (s.args.some((a) => /^[\w./-]+:latest$/.test(a) || (/^[\w./-]+$/.test(a) && a.includes('/') && !a.includes(':') && !a.startsWith('-')))) add('low', 'unpinned-image', 'uses a container image without a fixed version', null);
  }
  if (/server-filesystem|filesystem/.test(argv)) {
    const home = homeDir;
    if (s.args.some((a) => a === '/' || a === '~' || a === home || a === '$HOME' || a === '${HOME}')) add('medium', 'broad-filesystem', 'gives the agent file access to the whole disk or home folder', null);
  }
  if (s.scope === 'project' && s.command && !runner && /^\.{0,2}\//.test(s.command)) add('medium', 'repo-executable', "runs a program from the repository: anyone who can change the repo changes what runs on your machine", s.command);
  const counts = { high: 0, medium: 0, low: 0 };
  for (const x of f) if (x.severity in counts) counts[x.severity]++;
  const risk = counts.high ? 'high' : counts.medium ? 'medium' : counts.low ? 'low' : 'none';
  const hash = sha256(JSON.stringify({ c: s.command, a: s.args, u: s.url, e: Object.keys(s.env).sort(), h: Object.keys(s.headers).sort(), t: s.transport }));
  return { ...s, env: Object.keys(s.env), headers: Object.keys(s.headers), findings: f, counts, risk, hash };
}

/** @param {{ home?: string, cwd?: string, pinsFile?: string }} [opts] */
function auditServers({ home, cwd, pinsFile } = {}) {
  const pins = pinsFile ? (readJson(pinsFile) || {}) : {};
  return discoverServers({ home, cwd }).map((s) => {
    const a = auditServer(s, { home: home || os.homedir() });
    const key = `${a.client}|${a.scope}|${a.file}|${a.name}`;
    const p = pins[key];
    a.pin = !p ? 'new' : p === a.hash ? 'pinned' : 'changed';
    if (a.pin === 'changed') {
      a.findings.unshift({ severity: 'high', rule: 'changed-since-pinned', message: 'the server definition (command, arguments, URL or variables) changed since it was pinned', detail: null });
      a.counts.high++; a.risk = 'high';
    }
    a.pinKey = key;
    return a;
  });
}

function saveMcpPins(file, audits) {
  const pins = readJson(file) || {};
  for (const a of audits) pins[a.pinKey] = a.hash;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(pins, null, 2) + '\n', { mode: 0o600 });
}

// mcp__<server>__<tool>; plugin servers are mcp__plugin_<plugin>_<server>__<tool>.
function parseToolName(name) {
  const m = /^mcp__(.+)__([^_].*)$/.exec(name || '');
  if (!m) return null;
  let server = m[1];
  const tool = m[2];
  let plugin = null;
  const pm = /^plugin_([^_]+)_(.+)$/.exec(server);
  if (pm) { plugin = pm[1]; server = pm[2]; }
  return { server, tool, plugin, outbound: OUTBOUND.test(tool) };
}

// Match a used server name to configured definitions (names are normalized
// by clients: spaces and dots become underscores).
function configFor(audits, server) {
  const norm = (x) => String(x).toLowerCase().replace(/[^a-z0-9]+/g, '_');
  return audits.filter((a) => norm(a.name) === norm(server));
}

module.exports = { discoverServers, auditServer, auditServers, saveMcpPins, parseToolName, configFor, codexServers, SEV };
