'use strict';
// `blackbox scan`: a retroactive audit of existing Claude Code transcripts.
// Each past session is replayed offline through the same Policy the live hook
// uses, so the user sees what the firewall *would* have done, without
// installing anything. Read-only: nothing is written under ~/.claude and no
// network request is made. Only aggregate numbers leave this module, except
// for the opt-in --details list, whose reason text goes through redact().
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { Policy, redact, hostsIn } = require('./policy');
const { loadConfig } = require('./paths');

const DAY = 86400000;
const EGRESS_RULES = new Set(['egress', 'secret-egress', 'sensitive-egress', 'lethal-trifecta']);
const DENY_RULES = new Set(['secret-egress', 'sensitive-egress']);
// Rules worth listing per session in --details (plain egress is too common).
const FLAG_RULES = new Set(['secret-egress', 'sensitive-egress', 'lethal-trifecta', 'self-protection', 'hook-tamper']);

// Tool categories, in a fixed order: the order is also the color order in the
// HTML report, so a category keeps its color everywhere.
const CATEGORIES = [
  { id: 'shell', label: 'Shell' },
  { id: 'read', label: 'Read & search' },
  { id: 'edit', label: 'Edit & write' },
  { id: 'web', label: 'Web' },
  { id: 'mcp', label: 'MCP' },
  { id: 'agents', label: 'Agents & planning' },
  { id: 'other', label: 'Other' },
];
function categoryOf(name) {
  if (/^mcp__/.test(name)) return 'mcp';
  if (/^(Bash|PowerShell|BashOutput|KillShell|KillBash|Monitor)$/.test(name)) return 'shell';
  if (/^(Read|Grep|Glob|LS|NotebookRead|ListMcpResourcesTool|ReadMcpResourceTool)$/.test(name)) return 'read';
  if (/^(Edit|Write|MultiEdit|NotebookEdit)$/.test(name)) return 'edit';
  if (/^(WebFetch|WebSearch)$/.test(name)) return 'web';
  if (/^(Task|Agent|Todo\w*|Task\w+|Skill|Workflow|SendMessage|ExitPlanMode|EnterPlanMode|EnterWorktree|ExitWorktree)$/.test(name)) return 'agents';
  return 'other';
}

// First program of each segment of a shell command (`cd x && npm test | tee`
// -> cd, npm, tee). Names only: arguments never leave this function.
function programsOf(cmd) {
  const out = [];
  // Inline scripts are not programs: drop heredoc bodies and quoted strings.
  const text = String(cmd || '')
    .split(/<<-?\s*['"]?[A-Za-z_]+['"]?/)[0]
    .replace(/'[^']*'|"(?:\\.|[^"\\])*"/g, ' ');
  for (const seg of text.split(/&&|\|\||[;|\n]/)) {
    const words = seg.trim().replace(/^\(+/, '').split(/\s+/).filter((w) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w));
    let w = words[0];
    if (w === 'sudo' || w === 'time' || w === 'exec' || w === 'nohup') w = words[1];
    if (!w) continue;
    w = w.replace(/^["']|["']$/g, '').split('/').pop();
    if (/^[A-Za-z0-9._+-]{1,32}$/.test(w)) out.push(w);
  }
  return out;
}

const bump = (map, key, by = 1) => map.set(key, (map.get(key) || 0) + by);
const top = (map, k) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, k);

function defaultProjectsDir() {
  const base = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
  return path.join(base, 'projects');
}

// Session files live at projects/<cwd>/<id>.jsonl; subagent transcripts sit
// deeper (<id>/subagents/agent-*.jsonl), so walk a few levels.
function findFiles(dir, minMtime, depth = 0, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory() && depth < 4) findFiles(p, minMtime, depth + 1, out);
    else if (e.isFile() && e.name.endsWith('.jsonl')) {
      try { const st = fs.statSync(p); if (st.mtimeMs >= minMtime) out.push({ file: p, mtime: st.mtimeMs }); } catch { /* vanished */ }
    }
  }
  return out;
}

// Line iterator over a file in fixed-size chunks: transcripts can be far
// larger than we want to hold as one string.
function* lines(file) {
  let fd;
  try { fd = fs.openSync(file, 'r'); } catch { return; }
  const buf = Buffer.alloc(1 << 20);
  let rest = '';
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (!n) break;
      const chunk = rest + buf.toString('utf8', 0, n);
      const parts = chunk.split('\n');
      rest = parts.pop();
      yield* parts;
    }
    if (rest) yield rest;
  } finally { fs.closeSync(fd); }
}
// Note: a multi-byte UTF-8 char split across chunks decodes as U+FFFD on both
// sides; that only touches text content, never the JSON structure we rely on.

const textOfResult = (content) => (typeof content === 'string' ? content
  : Array.isArray(content) ? content.filter((b) => b && b.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n')
    : '');

// Transcripts store Read output with "   12\t" (or "12→") line-number prefixes.
// The live hook gets { file: { content } } without them, and KEY=value
// detection is anchored at line start, so rebuild that shape.
function toolResponse(tool, text) {
  if (tool === 'Read') return { file: { content: text.replace(/^ *\d+(?:\t|→)/gm, '') } };
  return text;
}

function humanPrompt(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content) || content.some((b) => b && b.type === 'tool_result')) return null;
  const t = textOfResult(content);
  return t || null;
}

function scan({ projectsDir = defaultProjectsDir(), days = 30, now = Date.now(), cfg = loadConfig() } = {}) {
  const policy = new Policy(cfg, { sessions: {} }, crypto.randomBytes(32));
  const files = findFiles(projectsDir, now - days * DAY).sort((a, b) => a.mtime - b.mtime);

  const sessions = new Map(); // id -> { first, last, tools, private, untrusted, rules:Set }
  // A session can move between directories (and span files), so project
  // numbers follow each entry's own cwd rather than one cwd per session.
  const projects = new Map(); // basename -> { sessions:Set, toolCalls, flagged:Set }
  const toolCounts = new Map();
  const catCounts = new Map();
  const dayCats = new Map(); // YYYY-MM-DD -> Map(category -> calls)
  const programs = new Map();
  const hosts = new Map(); // host -> { calls, kind }
  const allowed = (h) => (cfg.allowHosts || []).some((a) => h === a || h.endsWith('.' + a));
  const flagged = [];
  const flaggedKey = new Set();
  const t = { toolCalls: 0, outboundCalls: 0, wouldDenyCalls: 0, wouldAskCalls: 0, malformedLines: 0 };
  const ruleCounts = {};
  let first = null, last = null;

  const sess = (id, e) => {
    let s = sessions.get(id);
    if (!s) sessions.set(id, (s = { id, first: null, last: null, tools: 0, private: false, untrusted: false, rules: new Set() }));
    if (e.timestamp) {
      if (!s.first || e.timestamp < s.first) s.first = e.timestamp;
      if (!s.last || e.timestamp > s.last) s.last = e.timestamp;
      if (!first || e.timestamp < first) first = e.timestamp;
      if (!last || e.timestamp > last) last = e.timestamp;
    }
    return s;
  };

  for (const { file } of files) {
    const fallbackId = path.basename(file, '.jsonl');
    const pending = new Map(); // tool_use_id -> { name, input, session_id }
    for (const line of lines(file)) {
      if (!line.trim()) continue;
      let e;
      try { e = JSON.parse(line); } catch { t.malformedLines++; continue; }
      if (!e || (e.type !== 'assistant' && e.type !== 'user')) continue;
      const content = e.message && e.message.content;
      const session_id = e.sessionId || fallbackId;
      const s = sess(session_id, e);
      const project = e.cwd ? path.basename(e.cwd) : '(unknown)';
      let proj = projects.get(project);
      if (!proj) projects.set(project, (proj = { sessions: new Set(), toolCalls: 0, flagged: new Set(), categories: new Map() }));
      proj.sessions.add(session_id);

      if (e.type === 'assistant') {
        if (!Array.isArray(content)) continue;
        for (const b of content) {
          if (!b || b.type !== 'tool_use' || typeof b.name !== 'string') continue;
          const tool_input = b.input && typeof b.input === 'object' ? b.input : {};
          t.toolCalls++; s.tools++; proj.toolCalls++;
          toolCounts.set(b.name, (toolCounts.get(b.name) || 0) + 1);
          const cat = categoryOf(b.name);
          bump(catCounts, cat);
          bump(proj.categories, cat);
          const dk = e.timestamp ? String(e.timestamp).slice(0, 10) : null;
          if (dk) { if (!dayCats.has(dk)) dayCats.set(dk, new Map()); bump(dayCats.get(dk), cat); }
          if (cat === 'shell' && typeof tool_input.command === 'string') {
            for (const prog of programsOf(tool_input.command)) bump(programs, prog);
          }
          const targets = b.name === 'WebFetch' && typeof tool_input.url === 'string' ? hostsIn(tool_input.url)
            : cat === 'shell' && typeof tool_input.command === 'string' ? hostsIn(tool_input.command) : [];
          for (const h of new Set(targets)) {
            const rec = hosts.get(h) || { calls: 0, kind: null };
            rec.calls++;
            const intent = (policy.session(session_id).intentHosts || []).some((a) => h === a || h.endsWith('.' + a));
            rec.kind = allowed(h) ? 'allowlisted' : intent ? 'named by you' : 'external';
            hosts.set(h, rec);
          }
          pending.set(b.id, { name: b.name, input: tool_input, session_id });
          let d = null;
          try { d = policy.preToolUse({ session_id, tool_name: b.name, tool_input, tool_use_id: b.id }); } catch { /* odd input */ }
          if (!d) continue;
          ruleCounts[d.rule] = (ruleCounts[d.rule] || 0) + 1;
          if (EGRESS_RULES.has(d.rule)) t.outboundCalls++;
          if (DENY_RULES.has(d.rule)) t.wouldDenyCalls++;
          if (d.rule === 'lethal-trifecta' || d.rule === 'hook-tamper') t.wouldAskCalls++;
          if (FLAG_RULES.has(d.rule)) {
            s.rules.add(d.rule);
            proj.flagged.add(session_id);
            const k = `${session_id}\0${d.rule}`;
            if (!flaggedKey.has(k)) {
              flaggedKey.add(k);
              flagged.push({ session: session_id, date: e.timestamp || null, project, rule: d.rule, reason: redact(d.reason || '') });
            }
          }
        }
      } else {
        const prompt = e.isMeta ? null : humanPrompt(content);
        if (prompt != null) {
          if (typeof policy.userPrompt === 'function') { try { policy.userPrompt({ session_id, prompt }); } catch { /* optional */ } }
          continue;
        }
        if (!Array.isArray(content)) continue;
        for (const b of content) {
          if (!b || b.type !== 'tool_result') continue;
          const call = pending.get(b.tool_use_id);
          if (!call) continue;
          pending.delete(b.tool_use_id);
          // A failed or refused call never delivered real content.
          if (b.is_error) continue;
          let r = null;
          try {
            r = policy.postToolUse({ session_id: call.session_id, tool_name: call.name, tool_input: call.input, tool_response: toolResponse(call.name, textOfResult(b.content)), tool_use_id: b.tool_use_id });
          } catch { /* odd input */ }
          const cs = sessions.get(call.session_id) || s;
          for (const taint of (r && r.taints) || []) {
            if (taint.flag === 'private') cs.private = true;
            if (taint.flag === 'untrusted') cs.untrusted = true;
          }
        }
      }
    }
  }

  const list = [...sessions.values()];
  const count = (fn) => list.filter(fn).length;
  return {
    scannedAt: new Date(now).toISOString(),
    days,
    files: files.length,
    sessions: list.length,
    range: { first, last },
    toolCalls: t.toolCalls,
    privateSessions: count((s) => s.private),
    untrustedSessions: count((s) => s.untrusted),
    bothTaintsSessions: count((s) => s.private && s.untrusted),
    outboundCalls: t.outboundCalls,
    trifectaSessions: count((s) => s.rules.has('lethal-trifecta')),
    wouldAskCalls: t.wouldAskCalls,
    wouldDenyCalls: t.wouldDenyCalls,
    wouldDenySessions: count((s) => s.rules.has('secret-egress') || s.rules.has('sensitive-egress')),
    flaggedSessions: count((s) => s.rules.size > 0),
    rules: ruleCounts,
    topTools: top(toolCounts, 15).map(([name, count]) => ({ name, count, category: categoryOf(name) })),
    categories: Object.fromEntries(CATEGORIES.map((c) => [c.id, catCounts.get(c.id) || 0])),
    daily: [...dayCats.keys()].sort().map((d) => ({ date: d, ...Object.fromEntries(CATEGORIES.map((c) => [c.id, dayCats.get(d).get(c.id) || 0])) })),
    shellPrograms: top(programs, 15).map(([name, count]) => ({ name, count })),
    hosts: [...hosts.entries()].sort((a, b) => b[1].calls - a[1].calls).slice(0, 20).map(([host, h]) => ({ host, calls: h.calls, kind: h.kind })),
    projects: Object.fromEntries([...projects].map(([name, p]) => [name, {
      sessions: p.sessions.size, toolCalls: p.toolCalls, flagged: p.flagged.size,
      categories: Object.fromEntries(CATEGORIES.map((c) => [c.id, p.categories.get(c.id) || 0])),
    }])),
    malformedLines: t.malformedLines,
    flagged: flagged.sort((a, b) => String(a.date).localeCompare(String(b.date))),
  };
}

// ---------- terminal report ----------

const day = (ts) => (ts ? String(ts).slice(0, 10) : '?');

function renderReport(summary, { color = (process.stdout.isTTY ? true : false), details = false } = {}) {
  const c = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const red = c(31), green = c(32), yellow = c(33), dim = c(2), bold = c(1), cyan = c(36);
  const S = summary;
  const n = (x) => Number(x).toLocaleString('en-US');
  const warn = (x, col) => (x ? col(n(x)) : green(n(x)));
  const out = [];
  out.push(bold(`agent-blackbox scan · last ${S.days} days`));
  if (!S.sessions) {
    out.push(dim('  no Claude Code sessions found in that window.'));
    return out.join('\n');
  }
  out.push(dim(`  ${n(S.sessions)} sessions · ${day(S.range.first)} → ${day(S.range.last)} · ${n(S.toolCalls)} tool calls`));
  out.push('');
  const row = (label, val) => out.push(`  ${label.padEnd(46)} ${val}`);
  row('sessions that read private data', warn(S.privateSessions, yellow));
  row('sessions that ingested untrusted content', warn(S.untrustedSessions, yellow));
  row('outbound calls (network, git push, MCP send)', warn(S.outboundCalls, yellow));
  row('sessions where the lethal trifecta would fire', warn(S.trifectaSessions, red));
  row('calls that would have been denied', warn(S.wouldDenyCalls, red));
  if (S.rules['self-protection'] || S.rules['hook-tamper']) {
    row('settings / evidence tampering attempts', warn((S.rules['self-protection'] || 0) + (S.rules['hook-tamper'] || 0), red));
  }
  // 256-color approximations of the report's category colors, same order
  const CAT_ANSI = [33, 208, 36, 214, 211, 28, 99];
  const paint = (i, str) => (color ? `\x1b[38;5;${CAT_ANSI[i]}m${str}\x1b[0m` : str);
  const cats = CATEGORIES.map((cdef, i) => ({ ...cdef, i, v: (S.categories || {})[cdef.id] || 0 }));
  const catMax = Math.max(1, ...cats.map((x) => x.v));
  if (S.toolCalls) {
    out.push('');
    out.push(bold('  tool calls by category'));
    for (const x of cats) {
      const w = Math.round((x.v / catMax) * 28);
      const share = Math.round((x.v / S.toolCalls) * 100);
      out.push(`    ${x.label.padEnd(18)} ${paint(x.i, '█'.repeat(w) || (x.v ? '▏' : ''))}${' '.repeat(Math.max(0, 29 - Math.max(w, x.v ? 1 : 0)))}${String(n(x.v)).padStart(6)}  ${dim(String(share).padStart(3) + '%')}`);
    }
  }
  if (S.topTools.length) {
    out.push('');
    out.push(bold('  top tools'));
    for (const t of S.topTools.slice(0, 8)) {
      const ci = CATEGORIES.findIndex((cdef) => cdef.id === t.category);
      out.push(`    ${String(n(t.count)).padStart(7)}  ${paint(ci < 0 ? 6 : ci, '■')} ${t.name}`);
    }
  }
  if ((S.shellPrograms || []).length) {
    out.push('');
    out.push(bold('  shell programs'));
    out.push('    ' + S.shellPrograms.slice(0, 10).map((p) => `${p.name} ${dim(n(p.count))}`).join('  ·  '));
  }
  if ((S.hosts || []).length) {
    out.push('');
    out.push(bold('  network destinations'));
    for (const h of S.hosts.slice(0, 8)) {
      const kind = h.kind === 'external' ? yellow(h.kind) : dim(h.kind);
      out.push(`    ${String(n(h.calls)).padStart(7)}  ${h.host.slice(0, 40).padEnd(40)} ${kind}`);
    }
  }
  const projects = Object.entries(S.projects).sort((a, b) => b[1].toolCalls - a[1].toolCalls);
  if (projects.length) {
    out.push('');
    out.push(bold('  projects') + dim('   (bar: share of each category)'));
    for (const [name, p] of projects.slice(0, 10)) {
      const pc = p.categories || {};
      let bar = '';
      if (p.toolCalls) {
        let used = 0;
        CATEGORIES.forEach((cdef, i) => {
          const v = pc[cdef.id] || 0;
          if (!v) return;
          const w = Math.max(1, Math.round((v / p.toolCalls) * 16));
          bar += paint(i, '█'.repeat(w));
          used += w;
        });
        bar += ' '.repeat(Math.max(0, 18 - used));
      }
      const main = CATEGORIES.map((cdef) => [cdef.label, pc[cdef.id] || 0]).filter(([, v]) => v).sort((a, b) => b[1] - a[1]).slice(0, 2)
        .map(([l, v]) => `${l.split(' ')[0].toLowerCase()} ${Math.round((v / (p.toolCalls || 1)) * 100)}%`).join(', ');
      out.push(`    ${name.slice(0, 28).padEnd(28)} ${String(p.sessions).padStart(3)} sess ${String(n(p.toolCalls)).padStart(6)} calls  ${color ? bar : ''}${dim(main)}${p.flagged ? '  ' + red(`${p.flagged} flagged`) : ''}`);
    }
    if (projects.length > 10) out.push(dim(`    … ${projects.length - 10} more`));
  }
  if (details) {
    out.push('');
    out.push(bold('  flagged sessions'));
    if (!S.flagged.length) out.push(dim('    none'));
    for (const f of S.flagged) {
      const col = DENY_RULES.has(f.rule) ? red : yellow;
      out.push(`    ${day(f.date)}  ${f.session}  ${f.project || '(unknown)'}  ${col(f.rule)}`);
      if (f.reason) out.push(dim(`      ${redact(f.reason)}`));
    }
  } else if (S.flagged.length) {
    out.push(dim(`\n  ${S.flagged.length} flagged events; rerun with --details to list them.`));
  }
  if (S.malformedLines) out.push(dim(`  (${S.malformedLines} unreadable transcript lines skipped)`));
  out.push('');
  out.push(dim('  Scanned locally; nothing was uploaded.'));
  out.push(`  To stop these going forward: ${cyan('blackbox install')}`);
  return out.join('\n');
}

// ---------- shareable SVG card ----------

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

// Numbers and fixed labels only: no paths, project names, tools, commands,
// prompts or session ids, so the card is safe to post publicly.
function renderCard(summary) {
  const S = summary;
  const n = (x) => Number(x || 0).toLocaleString('en-US');
  const tiles = [
    { v: S.sessions, l: 'sessions scanned', c: '#e6edf3' },
    { v: S.toolCalls, l: 'tool calls', c: '#e6edf3' },
    { v: S.privateSessions, l: 'sessions read private data', c: '#f0b429' },
    { v: S.outboundCalls, l: 'outbound calls', c: '#f0b429' },
    { v: S.trifectaSessions, l: 'lethal trifecta sessions', c: '#ff6b6b' },
    { v: S.wouldDenyCalls, l: 'calls that would be denied', c: '#ff6b6b' },
  ];
  const W = 1200, H = 630, cols = 3, tw = 340, th = 170, gx = 30, gy = 30;
  const x0 = (W - (cols * tw + (cols - 1) * gx)) / 2, y0 = 170;
  const range = S.range && S.range.first ? `${day(S.range.first)} to ${day(S.range.last)}` : `last ${S.days} days`;
  const font = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
  const body = tiles.map((t, i) => {
    const x = x0 + (i % cols) * (tw + gx), y = y0 + Math.floor(i / cols) * (th + gy);
    return `  <g transform="translate(${x},${y})">
    <rect width="${tw}" height="${th}" rx="16" fill="#161b22" stroke="#30363d"/>
    <text x="28" y="92" font-size="64" font-weight="700" fill="${t.c}">${esc(n(t.v))}</text>
    <text x="28" y="136" font-size="22" fill="#8b949e">${esc(t.l)}</text>
  </g>`;
  }).join('\n');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="${esc(font)}">
  <rect width="${W}" height="${H}" fill="#0d1117"/>
  <text x="${x0}" y="92" font-size="44" font-weight="700" fill="#e6edf3">${esc('What my AI coding agent did')}</text>
  <text x="${x0}" y="132" font-size="24" fill="#8b949e">${esc(`Claude Code history · ${range}`)}</text>
${body}
  <text x="${W / 2}" y="${H - 28}" font-size="20" fill="#6e7681" text-anchor="middle">${esc('agent-blackbox · scanned locally, nothing uploaded')}</text>
</svg>
`;
}

module.exports = { scan, renderReport, renderCard, defaultProjectsDir, CATEGORIES, categoryOf, programsOf };
