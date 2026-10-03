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

const NET_TOOL = /(?:^|[\s;&|(`$])(curl|curl\.exe|wget|wget2|nc|ncat|netcat|socat|telnet|ftp|tftp|sftp|scp|rsync|ssh|http|https|xh|aria2c|nslookup|dig|host|lftp|websocat|grpcurl)(?=\s|$)/;
// Network code inside a command: interpreters with inline networking, Node
// built-ins, PowerShell web cmdlets, raw TLS.
const NET_CODE = new RegExp([
  String.raw`\b(?:python3?|node|ruby|perl|deno|bun|php)\b[^|;]*(?:requests\.|urllib|http\.client|httpx|aiohttp|fetch\(|net\/http|socket|axios|XMLHttpRequest|Net::HTTP|https?\.(?:request|get)|LWP|IO::Socket|file_get_contents\(\s*['"]https?:)`,
  String.raw`require\(\s*['"](?:node:)?(?:https?|http2|net|tls|dgram)['"]\s*\)`,
  String.raw`\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b`, String.raw`Net\.WebClient`, String.raw`\bopenssl\s+s_client\b`,
].join('|'), 'i');
const DEV_TCP = /\/dev\/(tcp|udp)\//;
// Commands that publish data to a service. They count as egress even toward
// allowlisted hosts (a secret pasted into a public gist is still a leak): the
// allowlist is for downloads, not uploads.
const PUBLISH = [
  [/\bgit\s+push\b/, 'git push'],
  [/\bgh\s+gist\s+(?:create|new|edit)\b/, 'gh gist (publishes content)'],
  [/\bgh\s+(?:issue|pr|discussion)\s+(?:create|new|comment|edit|review)\b/, 'gh posts to an issue or pull request'],
  [/\bgh\s+release\s+(?:create|upload|edit)\b/, 'gh release upload'],
  [/\bgh\s+api\b.*\s(?:-f|-F|--field|--raw-field|--input|-X\s*(?:POST|PUT|PATCH|DELETE)|--method\s+(?:POST|PUT|PATCH|DELETE))\b/i, 'gh api write request'],
  [/\b(?:npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b|\bgem\s+push\b|\bdocker\s+push\b/, 'publishes a package or image'],
  [/\baws\s+s3\s+(?:cp|sync|mv)\b|\bgsutil\s+(?:cp|rsync|mv)\b|\brclone\s+(?:copy|sync|move|copyto)\b|\baz\s+storage\s+blob\s+upload/, 'cloud storage upload'],
  [/(?:^|[\s;&|(])(?:sendmail|mailx?|mutt|swaks|msmtp)(?=\s|$)/, 'sends email'],
];
// Commands that reach a host named in their arguments (downloads that can
// still carry data out in the URL): git remotes, package installs from URLs,
// browsers opened on a URL.
const FETCH_CMD = /\bgit\s+(?:clone|fetch|pull|ls-remote|submodule|remote\s+(?:add|set-url))\b|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b|\bpip3?\s+(?:install|download)\b|\buv\s+(?:pip\s+install|add)\b|\bcargo\s+install\b|\bgo\s+(?:get|install)\b|\bgem\s+install\b|\bcomposer\s+require\b|(?:^|[\s;&|(])(?:open|xdg-open|start|explorer)(?=\s)|\bgh\s+api\b/;
// Code the agent can run without a network tool in sight.
const HEREDOC_CODE = /\b(?:python3?|node|ruby|perl|php|deno|bun|bash|sh|zsh)\s+(?:-\s+|-s\s+)?(?:[^\s|;&<>]+\s+)*<<-?\s*['"]?\w+/;
const INLINE_CODE = /\b(?:python3?|node|ruby|perl|php|deno|bun|pwsh|powershell)\s+(?:-[\w-]+\s+)*(?:-c|-e|--eval|-r|-Command|eval)\b|\b(?:bash|sh|zsh|dash|ksh)\s+(?:-\w+\s+)*-c\b|(?:^|[\s;&|(])eval(?=\s)|\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:python3?|node|perl|ruby)\b|\bsource\s+<\(|<\(\s*curl/;
const SCRIPT_RUNNER = /\b(?:npm|pnpm|yarn|bun)\s+(?:run|test|start|exec|x)\b|\bnpx\b|\bbunx\b|(?:^|[\s;&|(])make(?=\s|$)|\bpytest\b|\bcargo\s+(?:run|test)\b|\bgo\s+(?:run|test)\b|(?:^|[\s;&|(])just(?=\s|$)|\bgradlew?\b|\bmvn\b|\btox\b|\bnox\b|\buv\s+run\b|\bpoetry\s+run\b/;
const INTERP_FILE = /(?:^|[;&|(]\s*|&&\s*|\|\|\s*|\s)(?:bash|sh|zsh|dash|ksh|fish|source|(?<=^|[;&|(]\s*)\.|python3?|node|deno(?:\s+run)?|bun(?:\s+run)?|ruby|perl|php|tsx|ts-node|osascript|pwsh|powershell)\s+(?:-[\w-]+\s+)*([^\s;&|<>]+)/g;
const DIRECT_EXEC = /(?:^|[;&|(]\s*)((?:\.{1,2}|~)?\/[^\s;&|<>]+)/g;
const NET_SOURCE = /\b(?:fetch\(|XMLHttpRequest|axios|requests\.|urllib|http\.client|httpx|aiohttp|socket\.|net\/http|Net::HTTP|https?\.request|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls)['"]|from\s+['"]node:(?:https?|net|dgram|tls)['"]|curl\s|wget\s|Invoke-WebRequest|WebSocket\(|\/dev\/tcp\/)/;

// Source code that can reach the network or the shell indirectly.
const DYNAMIC_SOURCE = /\b(?:child_process|execSync|spawnSync|exec\(|spawn\(|subprocess|os\.system|os\.popen|Runtime\.getRuntime|eval\(|new Function\(|ProcessBuilder|system\(|`[^`]*\$\()/;

// A copy of a shell command with the usual obfuscations undone, so c''url,
// "curl", \curl, cu$'r'l, $'\x63url' and curl${IFS}x all read as curl.
function normalizeCmd(cmd) {
  let s = String(cmd || '');
  s = s.replace(/\\\n/g, '');
  s = s.replace(/\$'((?:[^'\\]|\\.)*)'/g, (m, body) => body
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\(.)/g, '$1'));
  s = s.replace(/\$\{IFS\}|\$IFS\b/g, ' ');
  s = s.replace(/["']/g, '');
  s = s.replace(/\\(?=[A-Za-z0-9._\/-])/g, '');
  s = s.replace(/\$\{?[A-Za-z_][A-Za-z0-9_]*:?-?\}?(?=[A-Za-z])/g, ''); // c${x}url → curl (empty vars)
  return s;
}

function stripHeredocs(cmd) {
  return String(cmd || '').replace(/<<-?\s*(['"]?)(\w+)\1[^\n]*\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, (m) => m.split('\n')[0]);
}

// The command words only: heredoc bodies and quoted strings removed, so code
// or text inside them is not read as commands, files or redirections.
function shellSkeleton(cmd) {
  let s = String(cmd || '');
  s = s.replace(/<<-?\s*(['"]?)(\w+)\1[^\n]*\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, (m) => m.split('\n')[0]);
  s = s.replace(/'[^'\n]*'|"(?:[^"\\\n]|\\.)*"/g, '""');
  return s;
}

// Glob tokens in a command (e.g. ~/.bl*box, .b?ackbox/*) as regexes.
function globsIn(cmd) {
  const out = [];
  for (const tok of String(cmd).split(/[\s;&|()<>]+/)) {
    if (!/[*?[]/.test(tok)) continue;
    for (const seg of tok.split('/')) {
      if (!/[*?[]/.test(seg) || seg.replace(/[*?]/g, '').length < 2) continue;
      try { out.push(new RegExp('^' + seg.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$')); } catch { /* skip */ }
    }
  }
  return out;
}
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
// Text in a file the agent reads that tries to steer the agent: an instruction
// override, or a request addressed to an AI to send secrets or data somewhere.
// Plain agent guidance ("run npm test before committing") does not match, so
// reading a CLAUDE.md or CONTRIBUTING.md does not taint the session.
const OVERRIDE = /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b(?:instructions?|rules|prompts?|guidelines|directions)\b/i;
const EXFIL_ASK = /\b(?:send|post|upload|exfiltrate|forward|transmit|leak|reveal|curl|wget|email|submit|include|print|paste|append)\b[^\n]{0,120}?(?:\.env\b|\b(?:secrets?|credentials?|tokens?|api[_ -]?keys?|passwords?|private[_ -]keys?|ssh keys?|environment variables?|id_rsa|mnemonic|seed phrase)\b)/gi;
const AGENT_WORD = /\b(?:ai|llm|assistants?|agents?|claude|copilot|chatgpt|gpt|cursor|codex|model)s?\b/i;
const NEGATED = /(?:\b(?:do not|don't|dont|never|must not|should not|shouldn't|avoid|without|no)\b|\bnot to\b)[^.\n]{0,40}$/i;
const INVISIBLE_TAGS = /[\u{E0000}-\u{E007F}]{4,}/u;

// Returns why the text looks like a prompt injection, or null.
function injectionIn(text) {
  const t = String(text || '').slice(0, 400_000);
  if (INVISIBLE_TAGS.test(t)) return 'hidden Unicode tag characters';
  const o = OVERRIDE.exec(t);
  if (o && !NEGATED.test(t.slice(Math.max(0, o.index - 50), o.index))) return `instruction override ("${o[0].slice(0, 60)}")`;
  EXFIL_ASK.lastIndex = 0;
  let m;
  while ((m = EXFIL_ASK.exec(t))) {
    if (NEGATED.test(t.slice(Math.max(0, m.index - 50), m.index))) continue;
    const around = t.slice(Math.max(0, m.index - 300), m.index + m[0].length + 100);
    if (AGENT_WORD.test(around)) return `asks an AI to send secrets or data out ("${m[0].slice(0, 60)}")`;
  }
  return null;
}
// A URL whose path or query holds a long opaque blob (base64, a slug without
// words, a dump) can carry data out even toward an allowlisted host. Commit
// ids and checksums are long but not data, and slugs have many hyphens.
function urlCarriesData(text) {
  for (const m of String(text).matchAll(/\bhttps?:\/\/[^\s'"`<>]+/gi)) {
    let u;
    try { u = new URL(m[0]); } catch { continue; }
    const parts = [...u.pathname.split('/'), ...[...u.searchParams.values()]];
    for (const raw of parts) {
      let p = raw;
      try { p = decodeURIComponent(raw); } catch { /* keep raw */ }
      if (p.length < 40 || /^[0-9a-f]{40}$|^[0-9a-f]{64}$|^sha\d+-/i.test(p)) continue;
      if ((p.match(/-/g) || []).length > 2 || /\s/.test(p)) continue;
      return `URL to ${u.hostname} carries a long opaque value in its path or query`;
    }
  }
  return null;
}
const FILE_READER_CMD = /\b(?:cat|head|tail|less|more|bat|sed|awk|grep|rg|ag|xxd|strings)\b/;
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

// Files written or downloaded by a shell command (redirects, tee, curl -o).
function writtenBy(cmd) {
  const out = [];
  const n = normalizeCmd(shellSkeleton(cmd));
  for (const re of [/(?:^|[^<>&\d])>{1,2}\s*([^\s;&|<>]+)/g, /\btee\s+(?:-a\s+)?([^\s;&|<>]+)/g, /\b(?:curl|wget)\b[^;&|]*?\s-(?:o|O|-output|-output-document)[\s=]+([^\s;&|<>]+)/g, /\b(?:cp|mv|install)\s+(?:-\w+\s+)*[^\s;&|]+\s+([^\s;&|<>]+)/g, /\bchmod\s+\+?[0-7]*x?\s+([^\s;&|<>]+)/g]) {
    let m;
    while ((m = re.exec(n))) if (!/^\/dev\/|^&/.test(m[1])) out.push(m[1]);
  }
  return out;
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
  // protect: extra paths (the real data folder) the agent may never touch
  constructor(cfg, state, salt, { protect = [], readFile = null } = {}) {
    this.cfg = cfg;
    // readFile(path, cwd) -> text | null: lets the policy look inside a script
    // that existed before the session before it is run
    this.readFile = readFile;
    this.protect = protect.filter(Boolean);
    this.state = state; // { sessions: { id: { private, untrusted, secrets: [] } } }
    this.salt = salt;
  }

  session(id) {
    const s = (this.state.sessions[id] ||= { private: null, untrusted: null, secrets: [] });
    s.secrets ||= [];
    s.written ||= [];   // files the agent wrote or downloaded this session
    s.netFiles ||= [];  // ...of which contain network code
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
      const full = (input && input.command) || '';
      // Heredoc text written to a file is data, not a command, unless the
      // heredoc is fed to an interpreter (bash <<EOF … EOF runs it).
      const raw = HEREDOC_CODE.test(full) ? full : stripHeredocs(full);
      const cmd = normalizeCmd(raw);
      const both = (re) => re.test(raw) || re.test(cmd);
      const hosts = [...new Set([...hostsIn(raw), ...hostsIn(cmd)])];
      const external = hosts.filter((h) => !allowed(h, allow));
      const intended = external.length > 0 && external.every((h) => allowed(h, sessIntent));
      for (const [re, why] of PUBLISH) if (both(re)) return { yes: true, intended, why };
      const net = both(NET_TOOL) || both(NET_CODE) || both(DEV_TCP);
      // a known downloader with a URL in it, or an unresolvable command word next to a URL ($C https://…)
      const fetchy = hosts.length && (both(FETCH_CMD) || /(?:^|[;&|(]\s*)(?:\$\{?\w+\}?|\$\(|`)/.test(raw.trim()));
      if (net || fetchy) {
        if (hosts.length && !external.length) {
          const carries = urlCarriesData(raw) || urlCarriesData(cmd);
          return carries ? { yes: true, why: carries } : { yes: false, why: 'allowlisted hosts only' };
        }
        return { yes: true, intended, why: external.length ? `network call to ${external.join(', ')}` : 'network call to an unparsed destination' };
      }
      // No network tool in sight, but the command runs code that could do anything.
      const run = this.runsCode(full, cmd, sess);
      if (run) return { yes: true, opaque: !run.net, why: run.why };
      return { yes: false };
    }
    if (tool === 'WebFetch') {
      let u;
      try { u = new URL(input.url); } catch { return { yes: false }; }
      if (allowed(u.hostname, allow)) {
        const carries = urlCarriesData(input.url);
        return carries ? { yes: true, why: carries } : { yes: false };
      }
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

  // Does this command run code whose behavior the policy cannot see? Scripts
  // the agent wrote or downloaded this session, inline interpreter code, and
  // (once the agent has written files) test runners and package scripts.
  // Writing a script first must not be a way around the network rules.
  runsCode(raw, cmd, sess) {
    const written = (sess && sess.written) || [];
    const netFiles = (sess && sess.netFiles) || [];
    const base = (f) => f.replace(/^~\//, '').split('/').filter(Boolean).pop() || f;
    const match = (arg, list) => list.find((w) => w === arg || base(w) === base(arg) || w.endsWith('/' + arg.replace(/^\.\//, '')));
    const targets = [];
    const sk = normalizeCmd(shellSkeleton(raw));
    for (const re of [INTERP_FILE, DIRECT_EXEC]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(sk))) if (!/^-|^""$/.test(m[1])) targets.push(m[1]);
    }
    for (const t of targets) {
      const hit = match(t, written);
      if (!hit && this.readFile) {
        let body = null;
        try { body = this.readFile(t, sess && sess.cwd); } catch { /* unreadable: treated as before */ }
        if (body && NET_SOURCE.test(body)) return { net: true, why: `runs ${t}, an existing script with network code` };
      }
      if (hit) return { net: !!match(t, netFiles), why: match(t, netFiles) ? `runs ${t}, which the agent wrote this session with network code` : `runs ${t}, which the agent wrote or downloaded this session` };
    }
    if (INLINE_CODE.test(sk) || INLINE_CODE.test(normalizeCmd(sk))) return { net: false, why: 'runs inline or piped code' };
    if (HEREDOC_CODE.test(raw)) return { net: false, why: 'runs a script passed inline (heredoc)' };
    // git runs hooks the agent may have planted in .git/hooks
    if (written.some((w) => /(^|\/)\.git\/hooks\/|(^|\/)\.husky\//.test(w)) && /\bgit\s+(?:commit|merge|rebase|checkout|switch|pull|push|am)\b/.test(cmd)) return { net: false, why: 'git runs a hook the agent wrote this session' };
    // Test runners and package scripts run whatever the agent edited; they
    // count once it wrote code that does networking or runs commands itself.
    if (netFiles.length && (SCRIPT_RUNNER.test(raw) || SCRIPT_RUNNER.test(cmd))) return { net: false, why: `runs project scripts after the agent wrote ${base(netFiles[netFiles.length - 1])}, which has network or shell code` };
    return null;
  }

  // Is this target the evidence store? Normalized, with globs expanded.
  touchesEvidence(text) {
    const n = normalizeCmd(text);
    const names = ['.blackbox', ...this.protect.map((p) => p.split('/').filter(Boolean).pop())];
    if (/\.blackbox(\/|\b)/.test(text) || /\.blackbox(\/|\b)/.test(n)) return true;
    if (this.protect.some((p) => text.includes(p) || n.includes(p))) return true;
    return globsIn(n).some((re) => names.some((name) => re.test(name)));
  }

  // PreToolUse: decide. Returns null (no opinion) or { decision, rule, reason }.
  preToolUse(ev) {
    const tool = ev.tool_name;
    const input = ev.tool_input || {};
    const text = inputText(input);
    const sess = this.session(ev.session_id);
    if (ev.cwd) sess.cwd = ev.cwd;

    // 1. Self-protection: the agent must not read or alter its own evidence.
    if (this.touchesEvidence(text)) {
      sess.denied = { rule: 'self-protection', at: new Date().toISOString() };
      return { decision: 'deny', rule: 'self-protection', reason: 'Access to the agent-blackbox evidence store (~/.blackbox) is blocked for the agent.' };
    }
    if ((/(^|\/)\.claude\/settings(\.local)?\.json/.test(text) || /(^|\/)\.claude\/settings(\.local)?\.json/.test(normalizeCmd(text)) || /managed-settings\.json|\.claude\/plugins\//.test(normalizeCmd(text))) && /^(Edit|Write|MultiEdit|Bash|PowerShell|NotebookEdit)$/.test(tool)) {
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
    if (secretOut && out.opaque) {
      return { decision: 'ask', rule: 'secret-to-code', reason: `A secret this session read earlier (fingerprint ${secretOut}) is passed to code the policy cannot inspect (${out.why}).`, secret: secretOut };
    }
    if (secretOut && (out.yes || tool === 'WebSearch' || tool === 'WebFetch' || this.mcpServer(tool))) {
      return deny('secret-egress', `A secret this session read earlier (fingerprint ${secretOut}) appears in an outbound ${tool} call (${out.why || tool}).`, { secret: secretOut });
    }
    // 3. One command that both reads a sensitive file and sends data out.
    if (out.yes && readsSensitive && out.opaque) {
      return { decision: 'ask', rule: 'sensitive-to-code', reason: `This command reads a sensitive file and runs code the policy cannot inspect (${out.why}).` };
    }
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
      if (mode === 'monitor' || (out.opaque && this.cfg.opaqueCode === 'alert')) return { decision: 'alert', rule: 'lethal-trifecta', reason };
      if (mode === 'deny' && !out.opaque) return deny('lethal-trifecta', reason);
      return { decision: 'ask', rule: 'lethal-trifecta', reason };
    }
    // 5. After a denial, any outbound call needs the human.
    if (out.yes && sess.denied && this.cfg.mode !== 'monitor') {
      return { decision: 'ask', rule: 'post-denial', reason: `An earlier call in this session was blocked (${sess.denied.rule}); this one sends data out (${out.why}).` };
    }
    if (out.yes) return { decision: 'note', rule: out.opaque ? 'runs-code' : 'egress', reason: out.why };
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
    // files the agent reads can carry planted instructions (a README, an issue
    // export, a dependency); only text that reads like an attack taints the session
    if (!untrusted && (tool === 'Read' || tool === 'Grep' || ((tool === 'Bash' || tool === 'PowerShell') && FILE_READER_CMD.test(input.command || '')))) {
      const why = injectionIn(respText);
      if (why) untrusted = `${tool} ${(input.file_path || input.path || input.pattern || input.command || '').slice(0, 60)}: ${why}`;
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
    // remember what the agent wrote, so running it later is not a blind spot
    const wrote = [];
    if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) wrote.push(input.file_path || input.notebook_path);
    if (tool === 'Bash' || tool === 'PowerShell') wrote.push(...writtenBy(input.command || ''));
    const body = [input.content, input.new_string, input.new_source, ...((input.edits || []).map((e) => e.new_string)), tool === 'Bash' ? input.command : null].filter((x) => typeof x === 'string').join('\n');
    for (const f of wrote.filter(Boolean)) {
      if (!sess.written.includes(f)) sess.written = [...sess.written, f].slice(-500);
      if ((NET_SOURCE.test(body) || DYNAMIC_SOURCE.test(body) || /\b(?:curl|wget)\b[^;&|]*\s-(?:o|O)\b/.test(input.command || '')) && !sess.netFiles.includes(f)) sess.netFiles = [...sess.netFiles, f].slice(-500);
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

module.exports = { Policy, injectionIn, inputText, textOf, stringsOf, hostsIn, normalizeCmd, writtenBy, redact, AGENT_DENY_MESSAGE };
