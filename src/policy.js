'use strict';
// "Lethal trifecta" policy: an agent session becomes dangerous when it has
// (1) touched private data, (2) ingested untrusted content, and (3) tries to
// send something out. Each condition alone is normal; together they are the
// shape of a prompt-injection exfiltration.
const crypto = require('crypto');

const SENSITIVE_PATH = [
  /(^|[\/\s'"=@<])\.env(\.[\w-]+)?(\b|$)/i,
  /\.ssh\//, /\bid_(rsa|dsa|ecdsa|ed25519)\b/,
  /\.aws\/(credentials|config)/, /\.netrc\b/, /\.npmrc\b/, /\.pypirc\b/,
  /\.git-credentials\b/, /\.docker\/config\.json/, /\.kube\/config/,
  /\.gnupg\//, /\.(pem|p12|pfx|key)\b/, /credentials?\.json/i,
  /keystores?\//i, /\bmnemonic\b/i, /seed[_-]?phrase/i,
  /\.blackbox\//, /Library\/Keychains/,
];

const SECRET_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}/g,
  /\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\bglpat-[A-Za-z0-9_\-]{20,}/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}/g,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}/g,
  /\bAIza[0-9A-Za-z_\-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const PRIVATE_KEY_FULL = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const TOKEN = /[A-Za-z0-9_\-+\/=.:]{8,}/g;
// KEY=value lines in .env-style content
const ENV_SECRET_LINE = /^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PRIVATE|MNEMONIC|SEED|CREDENTIAL|AUTH)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'#]{8,})/gim;

const NET_TOOL = /(?:^|[\s;&|(`$])(curl|wget|nc|ncat|netcat|socat|telnet|ftp|sftp|scp|rsync|ssh|http|https|xh|aria2c|nslookup|dig)(?=\s|$)/;
const NET_CODE = /\b(python3?|node|ruby|perl|deno|bun|php)\b[^|;]*(requests\.|urllib|http\.client|fetch\(|net\/http|socket|axios|XMLHttpRequest|Net::HTTP|https?\.request)/;
const DEV_TCP = /\/dev\/(tcp|udp)\//;
const GIT_PUSH = /\bgit\s+push\b/;
// Commands whose output is credentials: environment dumps and CLI token getters.
// Debug output fed back to the model was the main credential leak channel in
// "How Your Credentials Are Leaked by LLM Agent Skills" (arXiv:2604.03070).
const CREDENTIAL_CMD = new RegExp([
  String.raw`(?:^|[\s;&|(])(?:printenv|env)(?=\s*(?:$|[;&|>)]))`,
  String.raw`(?:^|[\s;&|(])set(?=\s*(?:$|[;&|>)]))`,
  String.raw`\bexport\s+-p\b`, String.raw`\bdeclare\s+-[xp]\b`, String.raw`\/proc\/[^\s]*\/environ\b`,
  String.raw`\bgh\s+auth\s+(?:token|status\s+--show-token)`, String.raw`\bgcloud\s+auth\s+(?:print-access-token|print-identity-token)`,
  String.raw`\baws\s+(?:configure\s+(?:get|export-credentials)|sts\s+get-session-token|secretsmanager\s+get-secret-value|ssm\s+get-parameters?)`,
  String.raw`\bkubectl\s+get\s+secrets?\b`, String.raw`\bsecurity\s+find-(?:generic|internet)-password\b`,
  String.raw`\bop\s+(?:read|item\s+get)\b`, String.raw`\bvault\s+(?:kv\s+get|read)\b`, String.raw`\bheroku\s+auth:token\b`,
  String.raw`\bnpm\s+token\b`, String.raw`\bdocker\s+inspect\b`,
].join('|'));
const MCP_OUTBOUND = /(send|post|create|write|upload|publish|email|mail|message|comment|reply|push|share|invite|request|fetch|http)/i;

function hostsIn(text) {
  const hosts = [];
  const re = /\b(?:https?|wss?|ftp):\/\/(?:[^@\/\s'"`]+@)?([^\/\s'"`:?#]+)/gi;
  let m;
  while ((m = re.exec(text))) hosts.push(m[1].toLowerCase());
  const scp = /(?:^|\s)[\w.-]+@([\w.-]+):/g;
  while ((m = scp.exec(text))) hosts.push(m[1].toLowerCase());
  return hosts;
}

const allowed = (host, allow) => allow.some((a) => host === a || host.endsWith('.' + a));

// All string leaves of a value, one per line. Tool results arrive as nested
// JSON (e.g. Read returns { file: { content } }); JSON.stringify would turn the
// newlines inside them into "\\n" and hide KEY=value lines from the scanner.
function stringsOf(v, out = [], budget = { left: 2_000_000 }) {
  if (budget.left <= 0 || v == null) return out;
  if (typeof v === 'string') { out.push(v.slice(0, budget.left)); budget.left -= v.length; }
  else if (Array.isArray(v)) for (const x of v) stringsOf(x, out, budget);
  else if (typeof v === 'object') for (const x of Object.values(v)) stringsOf(x, out, budget);
  return out;
}

function textOf(v, max = 2_000_000) {
  if (v == null) return '';
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return s.length > max ? s.slice(0, max) : s;
}

// Only the fields that name a target (a path, a command, a URL). File
// contents being written are not targets: a README that mentions ~/.env
// must not look like an access to it.
function inputText(toolInput) {
  if (!toolInput) return '';
  const t = toolInput;
  return [t.command, t.file_path, t.notebook_path, t.path, t.url, t.pattern, t.glob, t.skill]
    .filter((x) => typeof x === 'string').join('\n');
}

class Policy {
  constructor(cfg, state, salt) {
    this.cfg = cfg;
    this.state = state; // { sessions: { id: { private, untrusted, secrets: [] } } }
    this.salt = salt;
  }

  session(id) {
    const s = (this.state.sessions[id] ||= { private: null, untrusted: null, secrets: [] });
    s.secrets ||= [];
    return s;
  }

  mac(value) {
    return crypto.createHmac('sha256', this.salt).update(value).digest('hex').slice(0, 32);
  }

  extractSecrets(text) {
    const found = new Set();
    for (const re of SECRET_PATTERNS) for (const m of text.matchAll(re)) found.add(m[0]);
    for (const m of text.matchAll(ENV_SECRET_LINE)) found.add(m[2]);
    return [...found];
  }

  // Short public id for a secret: lets the ledger say "secret a91f… was read
  // at #5 and tried to leave at #12" without ever storing the secret.
  fingerprint(value) { return this.mac(value).slice(0, 12); }

  // Returns the fingerprint of the first known secret found in text, or null.
  containsKnownSecret(sess, text) {
    if (!sess.secrets.length || !text) return null;
    const known = new Set(sess.secrets);
    for (const m of text.matchAll(TOKEN)) {
      const tok = m[0];
      if (known.has(this.mac(tok))) return this.fingerprint(tok);
      // also catch the value inside KEY=value or key:value
      for (const part of tok.split(/[=:]/)) if (part.length >= 8 && known.has(this.mac(part))) return this.fingerprint(part);
    }
    return null;
  }

  // Replace secrets with [secret:<fingerprint>] before anything is written to
  // disk: pattern matches, KEY=value lines, private key blocks, and any value
  // this session already learned is a secret.
  scrubText(text, sess) {
    let out = text.replace(PRIVATE_KEY_FULL, (m) => `[private-key:${this.fingerprint(m)}]`);
    for (const re of SECRET_PATTERNS) out = out.replace(re, (m) => `[secret:${this.fingerprint(m)}]`);
    out = out.replace(ENV_SECRET_LINE, (m, k, v) => (v.startsWith('[secret:') || v.startsWith('[private-key:') ? m : m.replace(v, `[secret:${this.fingerprint(v)}]`)));
    if (sess && sess.secrets && sess.secrets.length) {
      const known = new Set(sess.secrets);
      const hit = (t) => t.length >= 8 && known.has(this.mac(t));
      out = out.replace(TOKEN, (tok) => {
        if (hit(tok)) return `[secret:${this.fingerprint(tok)}]`;
        if (!/[=:]/.test(tok)) return tok;
        return tok.split(/([=:])/).map((p) => (hit(p) ? `[secret:${this.fingerprint(p)}]` : p)).join('');
      });
    }
    return out;
  }

  // Deep copy of any JSON value with every string scrubbed.
  scrub(value, sessionId) {
    const sess = sessionId ? this.state.sessions[sessionId] : null;
    const walk = (v) => {
      if (typeof v === 'string') return this.scrubText(v, sess);
      if (Array.isArray(v)) return v.map(walk);
      if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
      return v;
    };
    return walk(value);
  }

  // Hosts the human named in their own prompt count as intended destinations
  // for this session (least privilege that follows the user's request, after
  // Progent, arXiv:2504.11703). Pasted text and turns Claude Code starts on its
  // own are not the human's intent, so they never widen the list.
  userPrompt(ev) {
    const sess = this.session(ev.session_id);
    let text = String(ev.prompt || '');
    if (/<(task-notification|system-reminder|teammate-message)\b/.test(text)) return [];
    text = text.replace(/<pasted_content\b[^>]*>[\s\S]*?<\/pasted_content\b[^>]*>/g, ' ');
    const found = [];
    const re = /\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[\/:\s'"`)>,]|$)/gi;
    let m;
    while ((m = re.exec(text))) {
      const host = m[1].toLowerCase();
      if (/\.(js|ts|json|md|py|sh|txt|env|yml|yaml|toml|lock|log|html|css)$/.test(host)) continue; // file names
      found.push(host);
    }
    sess.intentHosts = [...new Set([...(sess.intentHosts || []), ...found])].slice(-200);
    return found;
  }

  mcpServer(tool) {
    const m = /^mcp__(.+?)__/.exec(tool || '');
    return m ? m[1] : null;
  }

  // Is this tool call an attempt to send data out of the machine?
  egress(tool, input, sess) {
    const allow = this.cfg.allowHosts;
    const sessIntent = (sess && sess.intentHosts) || [];
    if (tool === 'Bash' || tool === 'PowerShell') {
      const cmd = (input && input.command) || '';
      const net = NET_TOOL.test(cmd) || NET_CODE.test(cmd) || DEV_TCP.test(cmd);
      if (GIT_PUSH.test(cmd)) return { yes: true, why: 'git push' };
      if (!net) return { yes: false };
      const hosts = hostsIn(cmd);
      const external = hosts.filter((h) => !allowed(h, allow));
      if (hosts.length && !external.length) return { yes: false, why: 'allowlisted hosts only' };
      const intended = external.length > 0 && external.every((h) => allowed(h, sessIntent));
      return { yes: true, intended, why: external.length ? `network call to ${external.join(', ')}` : 'network call to an unparsed destination' };
    }
    if (tool === 'WebFetch') {
      let u;
      try { u = new URL(input.url); } catch { return { yes: false }; }
      if (allowed(u.hostname, allow)) return { yes: false };
      const longSegment = u.pathname.split('/').some((p) => p.length > 40);
      if (u.search.length > 1 || longSegment) {
        return { yes: true, intended: allowed(u.hostname.toLowerCase(), sessIntent), why: `URL to ${u.hostname} carries data in its path or query` };
      }
      return { yes: false };
    }
    const server = this.mcpServer(tool);
    if (server && MCP_OUTBOUND.test(tool.slice(tool.lastIndexOf('__') + 2))) {
      return { yes: true, why: `MCP tool ${tool} sends data out` };
    }
    return { yes: false };
  }

  // PreToolUse: decide. Returns null (no opinion) or { decision, rule, reason }.
  preToolUse(ev) {
    const tool = ev.tool_name;
    const input = ev.tool_input || {};
    const text = inputText(input);
    const sess = this.session(ev.session_id);

    // 1. Self-protection: the agent must not read or alter its own evidence.
    if (/\.blackbox(\/|\b)/.test(text)) {
      sess.denied = { rule: 'self-protection', at: new Date().toISOString() };
      return { decision: 'deny', rule: 'self-protection', reason: 'Access to the agent-blackbox evidence store (~/.blackbox) is blocked for the agent.' };
    }
    if (/(^|\/)\.claude\/settings(\.local)?\.json/.test(text) && /^(Edit|Write|MultiEdit|Bash|PowerShell|NotebookEdit)$/.test(tool)) {
      return { decision: 'ask', rule: 'hook-tamper', reason: 'The agent wants to change Claude Code settings, where the agent-blackbox hooks live.' };
    }

    const out = this.egress(tool, input, sess);
    const secretOut = this.containsKnownSecret(sess, stringsOf(input).join('\n'));
    const readsSensitive = SENSITIVE_PATH.some((re) => re.test(text));
    const deny = (rule, reason, extra = {}) => {
      // A denial teaches an attacker what is protected. Record it, and make
      // every later outbound call in this session ask (counterfactual edge,
      // after "Causality Laundering", arXiv:2604.04035).
      sess.denied = { rule, at: new Date().toISOString() };
      return { decision: 'deny', rule, reason, ...extra };
    };

    // 2. A secret value seen earlier in this session is about to leave.
    //    Denied even toward a host the user named: secrets are never sent by the agent.
    if (secretOut && (out.yes || tool === 'WebSearch' || tool === 'WebFetch' || this.mcpServer(tool))) {
      return deny('secret-egress', `A secret this session read earlier (fingerprint ${secretOut}) appears in an outbound ${tool} call (${out.why || tool}).`, { secret: secretOut });
    }
    // 3. One command that both reads a sensitive file and sends data out.
    if (out.yes && readsSensitive) {
      return deny('sensitive-egress', `This command reads a sensitive file and sends data out (${out.why}).`);
    }
    if (out.yes && out.intended) {
      return { decision: 'note', rule: 'egress-intended', reason: `${out.why} (destination named by the user)` };
    }
    // 4. The lethal trifecta.
    if (out.yes && sess.private && sess.untrusted) {
      const mode = this.cfg.mode;
      const reason = `Lethal trifecta: this session read private data (${sess.private.why}) and untrusted content (${sess.untrusted.why}), and now wants to send data out (${out.why}).`;
      if (mode === 'monitor') return { decision: 'alert', rule: 'lethal-trifecta', reason };
      if (mode === 'deny') return deny('lethal-trifecta', reason);
      return { decision: 'ask', rule: 'lethal-trifecta', reason };
    }
    // 5. After a denial, any outbound call needs the human.
    if (out.yes && sess.denied && this.cfg.mode !== 'monitor') {
      return { decision: 'ask', rule: 'post-denial', reason: `An earlier call in this session was blocked (${sess.denied.rule}); this one sends data out (${out.why}).` };
    }
    if (out.yes) return { decision: 'note', rule: 'egress', reason: out.why };
    return null;
  }

  // PostToolUse: update the session's taint. Returns a list of new taints.
  postToolUse(ev) {
    const tool = ev.tool_name;
    const input = ev.tool_input || {};
    const sess = this.session(ev.session_id);
    const taints = [];
    const respText = stringsOf(ev.tool_response).join('\n');
    const inText = inputText(input);
    const server = this.mcpServer(tool);

    // untrusted content entered the context
    let untrusted = null;
    if (tool === 'WebFetch') untrusted = `WebFetch ${input.url || ''}`.trim();
    else if (tool === 'WebSearch') untrusted = `WebSearch "${(input.query || '').slice(0, 60)}"`;
    else if (server && !this.cfg.trustedMcpServers.includes(server)) untrusted = `MCP ${tool}`;
    else if ((tool === 'Bash' || tool === 'PowerShell') && (NET_TOOL.test(input.command || '') || NET_CODE.test(input.command || ''))) {
      untrusted = `network output of: ${(input.command || '').slice(0, 80)}`;
    }
    if (untrusted && !sess.untrusted) {
      sess.untrusted = { why: untrusted, at: new Date().toISOString(), tool_use_id: ev.tool_use_id };
      taints.push({ flag: 'untrusted', why: untrusted });
    }

    // private data entered the context
    const secrets = this.extractSecrets(respText);
    const pathHit = SENSITIVE_PATH.find((re) => re.test(inText));
    let priv = null;
    const credCmd = (tool === 'Bash' || tool === 'PowerShell') && CREDENTIAL_CMD.test(input.command || '');
    if (pathHit) priv = `${tool} ${(input.file_path || input.command || input.path || '').slice(0, 80)}`;
    else if (credCmd) priv = `credential output of: ${(input.command || '').slice(0, 80)}`;
    else if (secrets.length || PRIVATE_KEY_BLOCK.test(respText)) priv = `secret-looking value in ${tool} output`;
    else if (server && this.cfg.privateMcpServers.includes(server)) priv = `MCP ${tool}`;
    if (priv && !sess.private) {
      sess.private = { why: priv, at: new Date().toISOString(), tool_use_id: ev.tool_use_id };
      taints.push({ flag: 'private', why: priv });
    }
    if (secrets.length) {
      const set = new Set(sess.secrets);
      for (const s of secrets) set.add(this.mac(s));
      sess.secrets = [...set].slice(-500);
    }
    return { taints, secretsSeen: secrets.length };
  }
}

// What the agent itself is told when a call is denied: no rule name, no
// fingerprint, no hint about what was detected (see Causality Laundering).
const AGENT_DENY_MESSAGE = 'Blocked by the local security policy. Do not retry or work around this; tell the user what you were trying to do and let them decide.';

// Mask secret-looking values so the human-readable ledger never holds them.
// Full payloads still live in the blob store (mode 0600) as the evidence.
function redact(text) {
  let out = String(text == null ? '' : text);
  for (const re of SECRET_PATTERNS) out = out.replace(re, (m) => m.slice(0, 6) + '…[redacted]');
  out = out.replace(ENV_SECRET_LINE, (m, k, v) => m.replace(v, '[redacted]'));
  out = out.replace(/\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|MNEMONIC|SEED|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*["'`]?)([^\s"'`#]{6,})/g, '$1[redacted]');
  out = out.replace(/((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*["']?)([^\s"'&]{4,})/gi, '$1[redacted]');
  return out;
}

module.exports = { Policy, inputText, textOf, stringsOf, hostsIn, redact, AGENT_DENY_MESSAGE };
