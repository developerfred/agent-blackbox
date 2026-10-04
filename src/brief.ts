// `blackbox brief`: a deterministic Markdown summary of one session, built only
// from ledger records. Same records in, same text out: no clock, no locale, no
// model. Meant to be pasted into a PR, a ticket or an AGENTS.md-style handoff.

import type { LedgerRecord } from './types';

const FILE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const SEALED = 'bbx1:';
const MAX_ROWS = 12;

/** Inline-code safe: no backticks, no newlines, bounded. */
const code = (s: unknown, n = 120): string => {
  const t = String(s ?? '').replace(/[`\r\n]+/g, ' ').trim();
  return '`' + (t.length > n ? t.slice(0, n - 1) + '…' : t) + '`';
};

/** A table cell. */
const cell = (s: unknown): string => String(s ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();

/** The text of a record's summary, or '' when it is sealed and not opened. */
const text = (r: LedgerRecord): string => (typeof r.summary === 'string' && !r.summary.startsWith(SEALED) ? r.summary : '');

function span(a: string, b: string): string {
  const ms = Date.parse(b) - Date.parse(a);
  if (!Number.isFinite(ms) || ms < 0) return '';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

/** `records`: every record of the ledger, or of one session. Null when the session has none. */
export function brief(records: LedgerRecord[], session: string): string | null {
  const rows = records.filter((r) => r.session_id === session && r.kind !== 'otel').sort((a, b) => a.seq - b.seq);
  if (!rows.length) return null;
  const first = rows[0];
  const last = rows[rows.length - 1];
  const start = rows.find((r) => r.event === 'SessionStart');
  const agent = rows.map((r) => r.agent).find((a) => typeof a === 'string') || 'claude';

  const prompts = rows.filter((r) => r.event === 'UserPromptSubmit' && text(r));
  const tools = new Map<string, number>();
  const files = new Map<string, number>();
  for (const r of rows) {
    if (r.event !== 'PreToolUse' || typeof r.tool_name !== 'string') continue;
    tools.set(r.tool_name, (tools.get(r.tool_name) || 0) + 1);
    if (FILE_TOOLS.has(r.tool_name)) {
      const target = text(r).slice(r.tool_name.length).trim();
      if (target) files.set(target, (files.get(target) || 0) + 1);
    }
  }
  const decisions = rows.filter((r) => r.kind === 'decision' && r.decision !== 'allow');
  const blocked = decisions.filter((r) => r.decision === 'deny' || r.decision === 'ask' || r.decision === 'alert');
  const taints = rows.filter((r) => r.kind === 'taint');
  const hosts = [...new Set(rows.filter((r) => r.kind === 'intent').flatMap((r) => (Array.isArray(r.hosts) ? r.hosts.map(String) : [])))].sort();

  const out: string[] = [];
  out.push(`# Session brief: ${code(session, 80)}`, '');
  out.push(blocked.length
    ? `**${blocked.length} decision${blocked.length > 1 ? 's' : ''} needed attention** (${[...new Set(blocked.map((r) => r.rule))].sort().join(', ')}).`
    : '**No decision needed attention.**', '');
  out.push(`- Agent: ${agent}`);
  if (start && typeof start.cwd === 'string') out.push(`- Project: ${code(start.cwd)}`);
  const d = span(first.ts, last.ts);
  out.push(`- Window: ${first.ts} to ${last.ts}${d ? ` (${d})` : ''}`);
  out.push(`- Records: #${first.seq} to #${last.seq} (${rows.length}); last hash ${code(String(last.hash).slice(0, 16), 20)}`);
  out.push(`- Tool calls: ${[...tools.values()].reduce((a, b) => a + b, 0)}, prompts: ${prompts.length}`, '');

  if (prompts.length) {
    out.push('## Prompts', '');
    for (const r of prompts.slice(0, MAX_ROWS)) out.push(`- #${r.seq} ${code(text(r), 140)}`);
    if (prompts.length > MAX_ROWS) out.push(`- … ${prompts.length - MAX_ROWS} more`);
    out.push('');
  }
  if (tools.size) {
    out.push('## Tools', '', '| Tool | Calls |', '|---|---|');
    for (const [name, n] of [...tools].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))) out.push(`| ${cell(name)} | ${n} |`);
    out.push('');
  }
  if (files.size) {
    out.push('## Files changed', '');
    const list = [...files].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [f, n] of list.slice(0, MAX_ROWS)) out.push(`- ${code(f)}${n > 1 ? ` (${n} edits)` : ''}`);
    if (list.length > MAX_ROWS) out.push(`- … ${list.length - MAX_ROWS} more`);
    out.push('');
  }
  if (hosts.length) out.push('## Hosts the prompts named', '', ...hosts.slice(0, MAX_ROWS).map((h) => `- ${code(h)}`), '');
  if (decisions.length) {
    out.push('## Decisions', '', '| Record | Decision | Rule | Why |', '|---|---|---|---|');
    for (const r of decisions.slice(0, MAX_ROWS)) out.push(`| #${r.seq} | ${cell(String(r.decision))} | ${cell(String(r.rule))} | ${cell(String(r.reason ?? '')).slice(0, 200)} |`);
    if (decisions.length > MAX_ROWS) out.push(`| | | | … ${decisions.length - MAX_ROWS} more |`);
    out.push('');
  }
  if (taints.length) {
    out.push('## What the session touched', '');
    for (const r of taints.slice(0, MAX_ROWS)) out.push(`- #${r.seq} ${cell(String(r.flag))}: ${cell(String(r.why ?? '')).slice(0, 160)}`);
    if (taints.length > MAX_ROWS) out.push(`- … ${taints.length - MAX_ROWS} more`);
    out.push('');
  }
  out.push('## Verify', '', `Check the chain with ${code('blackbox verify')}; read the events with ${code(`blackbox timeline ${session}`)}.`, '');
  return out.join('\n');
}
