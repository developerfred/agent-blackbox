// Skills: find the ones installed for any agent, audit their files for risky
// patterns, and pin their content so a later change ("rug pull") is noticed.
//
// A skill is instructions plus optional scripts that the agent loads into its
// context and may run. Three Claude Code features make a skill more than text:
// frontmatter `hooks` (commands that run for the rest of the session), the
// `!`command`` syntax (runs while the skill loads, before the model reads it)
// and `allowed-tools` (tools used without asking). The audit looks hardest there.
//
// Static analysis finds known-bad shapes; it cannot prove a skill is safe.
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { redact } from './policy';
import { readJson, sha256, isDir, isFile } from './util';
import type { Finding, Severity } from './types';

const MAX_FILES = 300;
const MAX_BYTES = 1024 * 1024;
export const SEVERITY: Record<string, number> = { high: 3, medium: 2, low: 1, info: 0, none: -1 };

// ---------- discovery ----------

function candidateRoots(home = os.homedir(), cwd = process.cwd()): { dir: string; source: string; deep?: boolean; commands?: boolean }[] {
  const claude = process.env.CLAUDE_CONFIG_DIR || path.join(home, '.claude');
  return [
    { dir: path.join(claude, 'skills'), source: 'claude personal' },
    { dir: path.join(claude, 'plugins'), source: 'claude plugin', deep: true },
    { dir: path.join(claude, 'commands'), source: 'claude command', commands: true },
    { dir: path.join(home, '.agents', 'skills'), source: 'agents (global)' },
    { dir: path.join(home, '.config', 'agents', 'skills'), source: 'agents (global)' },
    { dir: path.join(home, '.cursor', 'skills'), source: 'cursor' },
    { dir: path.join(home, '.codex', 'skills'), source: 'codex' },
    { dir: path.join(home, '.copilot', 'skills'), source: 'copilot' },
    { dir: path.join(cwd, '.claude', 'skills'), source: 'claude project' },
    { dir: path.join(cwd, '.claude', 'commands'), source: 'claude project command', commands: true },
    { dir: path.join(cwd, '.agents', 'skills'), source: 'agents (project)' },
  ];
}

const real = (p: string): string | null => { try { return fs.realpathSync(p); } catch { return null; } };

// Every directory under `dir` (up to `depth`) that holds a SKILL.md.
function findSkillDirs(dir: string, depth: number, out: string[] = []): string[] {
  if (depth < 0 || !isDir(dir)) return out;
  if (isFile(path.join(dir, 'SKILL.md'))) { out.push(dir); return out; }
  let entries: fs.Dirent[] = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    if (e.isDirectory() || e.isSymbolicLink()) findSkillDirs(path.join(dir, e.name), depth - 1, out);
  }
  return out;
}

export interface Skill { name: string; dir: string; file: string; files?: string[]; source: string; realpath: string; single?: boolean; plugin?: string }

export function discoverSkills({ home, cwd, extra = [] }: { home?: string; cwd?: string; extra?: string[] } = {}): Skill[] {
  const roots = [...candidateRoots(home, cwd), ...extra.map((d) => ({ dir: path.resolve(d), source: 'path', deep: false, commands: false }))];
  const seen = new Set<string>();
  const skills: Skill[] = [];
  for (const root of roots) {
    if (!isDir(root.dir)) continue;
    if (root.commands) {
      // legacy single-file commands: .claude/commands/*.md
      for (const f of fs.readdirSync(root.dir)) {
        const file = path.join(root.dir, f);
        const rp = real(file);
        if (!f.endsWith('.md') || !rp || seen.has(rp) || !isFile(file)) continue;
        seen.add(rp);
        skills.push({ name: f.replace(/\.md$/, ''), dir: root.dir, file, files: [file], source: root.source, realpath: rp, single: true });
      }
      continue;
    }
    for (const dir of findSkillDirs(root.dir, root.deep ? 7 : 3)) {
      const rp = real(dir);
      if (!rp || seen.has(rp)) continue;
      seen.add(rp);
      const file = path.join(dir, 'SKILL.md');
      const fm = parseFrontmatter(readText(file) || '');
      const synced = dir.includes(`${path.sep}synced${path.sep}`);
      skills.push({
        name: (typeof fm.name === 'string' && fm.name) || path.basename(dir),
        dir, file, source: synced ? 'claude synced' : root.source, realpath: rp,
        plugin: root.deep ? pluginOf(root.dir, dir) : undefined,
      });
    }
  }
  return skills;
}

function pluginOf(pluginsRoot: string, dir: string): string | undefined {
  const parts = path.relative(pluginsRoot, dir).split(path.sep);
  const i = parts.lastIndexOf('skills');
  return i > 0 ? parts[i - 1] : undefined;
}

// ---------- reading ----------

function readText(file: string): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const buf = fs.readFileSync(file);
    if (buf.includes(0)) return null; // binary
    return buf.toString('utf8');
  } catch { return null; }
}

function listFiles(dir: string, out: string[] = [], depth = 0): string[] {
  if (out.length >= MAX_FILES || depth > 6) return out;
  let entries: fs.Dirent[] = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory() || (e.isSymbolicLink() && isDir(p))) listFiles(p, out, depth + 1);
    else if (isFile(p)) out.push(p);
    if (out.length >= MAX_FILES) break;
  }
  return out;
}

// Minimal frontmatter reader: top-level keys, scalar or inline/block lists.
export function parseFrontmatter(text: string): Record<string, any> {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return {};
  const out: Record<string, any> = {};
  let key: string | null = null;
  for (const line of m[1].split(/\r?\n/)) {
    const top = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (top) {
      key = top[1];
      const v = top[2].trim();
      out[key] = v === '' ? [] : v.replace(/^["']|["']$/g, '');
    } else if (key && /^\s+-\s+/.test(line) && Array.isArray(out[key])) {
      out[key].push(line.replace(/^\s+-\s+/, '').replace(/^["']|["']$/g, ''));
    } else if (key && /^\s+\S/.test(line)) {
      if (Array.isArray(out[key])) out[key].push(line.trim()); else out[key] = [out[key], line.trim()];
    }
  }
  return out;
}

// ---------- rules ----------

const NET = String.raw`(?:curl|wget|nc|ncat|socat|scp|rsync|ftp|httpie|xh|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b`;
const RULES: { id: string; sev: Severity; re: RegExp; msg: string }[] = [
  { id: 'download-exec', sev: 'high', re: new RegExp(String.raw`\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^\n|]*\|\s*(?:python3?|node|perl|ruby)\b|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)|eval\s+["'$(]*\s*\$\(\s*(?:curl|wget)|\b(?:iex|Invoke-Expression)\b[^\n]*(?:iwr|Invoke-WebRequest|DownloadString)`, 'i'),
    msg: 'downloads code and runs it immediately' },
  { id: 'obfuscated-exec', sev: 'high', re: /base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:ba|z)?sh\b|\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(|\bexec\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex)|\bFromBase64String\b[^\n]*\b(?:iex|Invoke-Expression)\b/i,
    msg: 'decodes hidden content and executes it' },
  { id: 'persistence', sev: 'high', re: /\bcrontab\b|\blaunchctl\s+(?:load|bootstrap|submit)\b|Library\/LaunchAgents|Library\/LaunchDaemons|>>?\s*~?\/?(?:\$HOME\/)?\.(?:zshrc|bashrc|bash_profile|profile|zprofile)\b|\bsystemctl\s+(?:--user\s+)?enable\b|authorized_keys/i,
    msg: 'installs something that survives the session (startup files, cron, launch agents, SSH keys)' },
  { id: 'safety-bypass', sev: 'high', re: /--dangerously-skip-permissions|\bbypassPermissions\b|\bdisableAllHooks\b|\.claude\/settings(?:\.local)?\.json|\.blackbox\b|\bdisableSkillShellExecution\b/i,
    msg: "touches the agent's own safety settings, hooks or audit trail" },
  { id: 'destructive', sev: 'high', re: /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$)|~\/?(?:\s|$)|\$HOME\/?(?:\s|$)|\/\*)|\bmkfs(?:\.\w+)?\b|\bdd\b[^\n]*\bof=\/dev\/(?:sd|disk|nvme)/i,
    msg: 'can destroy files or disks' },
  { id: 'exfil-endpoint', sev: 'high', re: /discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|webhook\.site|requestbin|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|burpcollaborator|interact\.sh|\boast\.(?:fun|live|site|me|pro)\b|pastebin\.com\/api|transfer\.sh|api\.telegram\.org\/bot/i,
    msg: 'sends data to an endpoint commonly used for collecting stolen data' },
  { id: 'credential-access', sev: 'medium', re: /~\/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|\.npmrc\b|\.netrc\b|\.git-credentials\b|\bsecurity\s+find-(?:generic|internet)-password\b|\bprintenv\b|JSON\.stringify\(\s*process\.env\s*\)|console\.log\(\s*process\.env\s*\)|\bdict\(\s*os\.environ\s*\)|print\(\s*os\.environ\s*\)|(?:cat|less|source|\.)\s+[^\n]*\.env\b|\bgh\s+auth\s+token\b/i,
    msg: 'reads credentials or dumps environment variables' },
  { id: 'network-send', sev: 'medium', re: new RegExp(String.raw`\b(?:curl|wget)\b[^\n]*(?:\s-d\b|--data|\s-F\b|--form|\s-T\b|--upload-file|-X\s*(?:POST|PUT)|--post-(?:data|file))|\brequests\.(?:post|put)\(|\bfetch\([^\n]*method\s*:\s*["'](?:POST|PUT)|\bhttp\.request\([^\n]*method\s*:\s*["']POST|\b(?:nc|ncat)\s+[\w.-]+\s+\d{2,5}\b`, 'i'),
    msg: 'sends data over the network' },
];
const INJECTION = /\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|messages|rules)|\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|show|reveal|notify)\s+(?:this\s+to\s+)?the\s+user\b(?!\s+to\b)|\bwithout\s+(?:asking|telling|informing|notifying)\s+the\s+user\b|\b(?:silently|secretly|covertly)\s+(?:send|upload|post|copy|run|execute|exfiltrate)\b|\bnew\s+system\s+prompt\b|\byou\s+are\s+no\s+longer\b/i;
// Defensive text quotes attack phrases in order to forbid them.
const DEFENSIVE = /\b(?:do\s+not|don't|never)\s+(?:follow|obey|comply)|\bis\s+data\b|\bnot\s+instructions\b|\btreat\b[^.]*\bas\s+(?:data|untrusted)/i;
function quotedAt(line: string, index: number): boolean {
  const before = line.slice(Math.max(0, index - 3), index);
  return /["'“‘`]/.test(before);
}
const HIDDEN_UNICODE = /[\u{E0000}-\u{E007F}‪-‮⁦-⁩​-‏⁠⁡-⁤]/u;
const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const COMMENT_SUSPICIOUS = /\b(?:ignore|instruction|assistant|agent|ai\b|model|claude|system|do not|don't|curl|wget|send|upload|token|secret|password|\.env|ssh|execute|run)\b/i;
const LONG_B64 = /[A-Za-z0-9+/]{240,}={0,2}/;
const LOAD_CMD_INLINE = /(?:^|\s)!`([^`\n]+)`/g;
const LOAD_CMD_BLOCK = /```!\s*\n([\s\S]*?)```/g;
const SECRET_RES = [
  /\bAKIA[0-9A-Z]{16}\b/, /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/, /\b[rs]k_live_[A-Za-z0-9]{16,}/, /\bgh[pousr]_[A-Za-z0-9]{30,}/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}/, /\bxox[abpr]-[A-Za-z0-9-]{10,}/, /\bAIza[0-9A-Za-z_-]{35}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

const CODE_EXT = /\.(?:sh|bash|zsh|fish|ps1|py|js|mjs|cjs|ts|rb|pl|php|go|rs|lua)$/i;

function excerpt(line: string): string {
  const t = redact(line.trim().replace(/\s+/g, ' '));
  return t.length > 140 ? t.slice(0, 139) + '…' : t;
}

// Which lines of a markdown file sit inside fenced code blocks.
function fencedLines(lines: string[]): boolean[] {
  const inside: boolean[] = new Array(lines.length).fill(false);
  let open = false;
  lines.forEach((l, i) => {
    if (/^\s*```/.test(l)) { inside[i] = true; open = !open; return; }
    inside[i] = open;
  });
  return inside;
}

export function auditFile(file: string, rel: string, text: string, { isSkillMd }: { isSkillMd?: boolean }): Finding[] {
  const findings: Finding[] = [];
  const add = (sev: Severity, rule: string, line: number, message: string, ex?: string | null): number => findings.push({ severity: sev, rule, file: rel, line, message, excerpt: ex });
  const lines = text.split(/\r?\n/);
  const isCode = CODE_EXT.test(file) || /^#!/.test(text);
  const isMd = /\.md$/i.test(file);
  const fenced = isMd ? fencedLines(lines) : null;
  let hasNet = false, hasCred = false;
  let firstCred: number | null = null;

  lines.forEach((line, i) => {
    const ln = i + 1;
    if (HIDDEN_UNICODE.test(line)) add('high', 'hidden-unicode', ln, 'contains invisible or direction-changing characters that can hide instructions', excerpt(line.replace(/[\u{E0000}-\u{E007F}‪-‮⁦-⁩​-‏⁠-⁤]/gu, '⟨?⟩')));
    for (const r of RULES) {
      if (!r.re.test(line)) continue;
      // Commands shown in prose documentation are a lesser risk than code
      // that runs; commands in fenced blocks may still be run by the agent.
      let sev = r.sev;
      if (isMd && !(fenced && fenced[i]) && sev === 'high' && r.id !== 'exfil-endpoint') sev = 'medium';
      if (isMd && fenced && fenced[i] && sev === 'high' && (r.id === 'download-exec')) sev = 'medium';
      add(sev, r.id, ln, r.msg, excerpt(line));
      if (r.id === 'network-send' || r.id === 'exfil-endpoint') hasNet = true;
      if (r.id === 'credential-access') { hasCred = true; firstCred = firstCred || ln; }
    }
    if (new RegExp(`\\b${NET}`, 'i').test(line)) hasNet = true;
    if (SECRET_RES.some((re) => re.test(line))) add('high', 'hardcoded-secret', ln, 'contains what looks like a real credential', excerpt(line));
    const inj = INJECTION.exec(line);
    if (inj && !quotedAt(line, inj.index) && !DEFENSIVE.test(line)) add(isCode ? 'medium' : 'high', 'injection-phrase', ln, 'contains wording used to override instructions or hide actions from the user', excerpt(line));
    if (isMd && LONG_B64.test(line)) add('medium', 'encoded-blob', ln, 'contains a long encoded blob the reader cannot see', excerpt(line.slice(0, 60)));
  });

  if (hasCred && hasNet) {
    add(isCode ? 'high' : 'medium', 'credential-exfil', firstCred ?? 0, 'reads credentials and also talks to the network in the same file', null);
  }

  if (isMd) {
    for (const m of text.matchAll(HTML_COMMENT)) {
      if (!COMMENT_SUSPICIOUS.test(m[1])) continue;
      const ln = text.slice(0, m.index).split('\n').length;
      add('high', 'hidden-instruction', ln, 'an HTML comment (invisible when rendered) contains instructions or commands', excerpt(m[1]));
    }
  }

  if (isSkillMd) {
    const fm = parseFrontmatter(text);
    const fmLine = (k: string): number => { const i = lines.findIndex((l) => l.startsWith(k + ':')); return i < 0 ? 1 : i + 1; };
    if (fm.hooks !== undefined) add('high', 'skill-hooks', fmLine('hooks'), 'registers hooks: commands that keep running for the rest of the session once the skill is used', null);
    const tools = ([] as string[]).concat(fm['allowed-tools'] || []).join(' ');
    if (tools) {
      const broad = /(^|[\s,[])Bash(?:\(\s*\*\s*\)|\(\s*\*\s+\*\s*\))?(?=$|[\s,\]])/.test(tools) || /Bash\((?:curl|wget|sh|bash|zsh|python3?|node|perl|ruby|eval|sudo|nc)\b[^)]*\*\)/.test(tools);
      add(broad ? 'high' : 'low', 'allowed-tools', fmLine('allowed-tools'), broad ? 'pre-approves unrestricted shell or network/interpreter commands' : 'pre-approves some tools for the turn the skill runs', excerpt(tools));
    }
    for (const re of [LOAD_CMD_INLINE, LOAD_CMD_BLOCK]) {
      for (const m of text.matchAll(re)) {
        const cmd = m[1];
        const ln = text.slice(0, m.index).split('\n').length;
        const risky = RULES.some((r) => r.sev === 'high' && r.re.test(cmd)) || new RegExp(`\\b${NET}`, 'i').test(cmd) || RULES.find((r) => r.id === 'credential-access')?.re.test(cmd);
        add(risky ? 'high' : 'low', 'load-time-command', ln, risky ? 'runs a network or sensitive command automatically when the skill loads' : 'runs a command automatically when the skill loads', excerpt(cmd));
      }
    }
  }
  return findings;
}

function hashFiles(base: string, files: string[]): { hash: string; files: Record<string, string> } {
  const h = crypto.createHash('sha256');
  const per: Record<string, string> = {};
  for (const f of files) {
    let buf: Buffer;
    try { buf = fs.readFileSync(f); } catch { continue; }
    const rel = path.relative(base, f) || path.basename(f);
    per[rel] = sha256(buf);
    h.update(rel).update('\0').update(per[rel]).update('\n');
  }
  return { hash: h.digest('hex'), files: per };
}

export function auditSkill(skill: Skill) {
  const files = skill.single ? [skill.file] : listFiles(skill.dir);
  const base = skill.single ? path.dirname(skill.file) : skill.dir;
  let findings: Finding[] = [];
  for (const f of files) {
    const text = readText(f);
    if (text == null) continue;
    const rel = path.relative(base, f) || path.basename(f);
    findings = findings.concat(auditFile(f, rel, text, { isSkillMd: rel === 'SKILL.md' || skill.single }));
  }
  // one finding per rule per file line is plenty; keep the strongest
  const seen = new Map<string, Finding>();
  for (const x of findings) {
    const k = `${x.rule}\0${x.file}\0${x.line}`;
    if (!seen.has(k) || SEVERITY[x.severity] > SEVERITY[(seen.get(k) as Finding).severity]) seen.set(k, x);
  }
  findings = [...seen.values()].sort((a, b) => SEVERITY[b.severity] - SEVERITY[a.severity] || (a.file || '').localeCompare(b.file || '') || (a.line || 0) - (b.line || 0));
  const counts = { high: 0, medium: 0, low: 0 };
  for (const x of findings) if (x.severity in counts) counts[x.severity as keyof typeof counts]++;
  const risk: Severity = counts.high ? 'high' : counts.medium ? 'medium' : counts.low ? 'low' : 'none';
  return { ...skill, fileCount: files.length, findings, counts, risk, ...hashFiles(base, files) };
}

// ---------- pins ----------

export const loadPins = (file: string): Record<string, any> => readJson(file, {});

function comparePin(pins: Record<string, any>, a: { realpath: string; hash: string; files: Record<string, string> }): { status: 'new' | 'pinned' | 'changed'; changed?: string[]; pinnedAt?: string } {
  const p = pins[a.realpath];
  if (!p) return { status: 'new' };
  if (p.hash === a.hash) return { status: 'pinned' };
  const changed = Object.keys({ ...p.files, ...a.files }).filter((f) => p.files[f] !== a.files[f]);
  return { status: 'changed', changed, pinnedAt: p.pinnedAt };
}

export function savePins(file: string, audits: any[]): Record<string, any> {
  const pins = loadPins(file);
  const now = new Date().toISOString();
  for (const a of audits) pins[a.realpath] = { name: a.name, source: a.source, hash: a.hash, files: a.files, pinnedAt: now };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(pins, null, 2) + '\n', { mode: 0o600 });
  return pins;
}

export function auditAll({ home, cwd, extra, pinsFile }: { home?: string; cwd?: string; extra?: string[]; pinsFile?: string } = {}) {
  const pins = pinsFile ? loadPins(pinsFile) : {};
  return discoverSkills({ home, cwd, extra }).map((s) => {
    const a = auditSkill(s);
    const pin = comparePin(pins, a);
    if (pin.status === 'changed') {
      a.findings.unshift({ severity: 'high', rule: 'changed-since-pinned', file: (pin.changed || []).slice(0, 5).join(', '), line: 0, message: `content changed since it was pinned on ${String(pin.pinnedAt).slice(0, 10)}`, excerpt: null });
      a.counts.high++;
      a.risk = 'high';
    }
    return { ...a, pin };
  });
}

// Look up a skill by the name the agent used ("docs", "plugin:skill",
// "anthropic-skills:docs"). Returns the riskiest match.
export function riskFor<A extends { name: string; dir: string; risk: string; plugin?: string; source: string }>(audits: A[], invoked: unknown): A | null {
  const name = String(invoked || '').trim();
  if (!name) return null;
  const short = name.split(':').pop();
  const plugin = name.includes(':') ? name.split(':')[0] : null;
  const matches = audits.filter((a) => a.name === name || a.name === short || path.basename(a.dir) === short)
    .filter((a) => !plugin || !a.plugin || a.plugin === plugin || a.source !== 'claude plugin');
  return matches.sort((a, b) => SEVERITY[b.risk] - SEVERITY[a.risk])[0] || null;
}
