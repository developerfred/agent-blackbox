'use strict';
// `blackbox scan --html`: a local, self-contained report of what the agent
// did, built from the scan summary. No external scripts, fonts or requests.
// It contains project names, program names and hosts (never commands,
// prompts or secrets), so it is meant for you; share the --card instead.
const { CATEGORIES } = require('./scan');

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const n = (x) => Number(x || 0).toLocaleString('en-US');
const pct = (a, b) => (b ? `${Math.round((a / b) * 100)}%` : '0%');

// Bar with a square base and a 4px rounded data end (horizontal).
function hbar(x, y, w, h, r = 4) {
  if (w <= 0) return '';
  const rr = Math.min(r, w, h / 2);
  return `M${x} ${y}h${w - rr}a${rr} ${rr} 0 0 1 ${rr} ${rr}v${h - 2 * rr}a${rr} ${rr} 0 0 1 -${rr} ${rr}h-${w - rr}z`;
}
// Column with a square base on the baseline and a rounded top.
function vbar(x, yBase, w, h, r = 4) {
  if (h <= 0) return '';
  const rr = Math.min(r, h, w / 2);
  return `M${x} ${yBase}v-${h - rr}a${rr} ${rr} 0 0 1 ${rr} -${rr}h${w - 2 * rr}a${rr} ${rr} 0 0 1 ${rr} ${rr}v${h - rr}z`;
}

const catVar = (i) => `var(--series-${i + 1})`;
const catLabel = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.label]));

function legend() {
  return `<ul class="legend">${CATEGORIES.map((c, i) => `<li><span class="sw" style="background:${catVar(i)}"></span>${esc(c.label)}</li>`).join('')}</ul>`;
}

function table(head, rows) {
  return `<details class="data"><summary>Show data table</summary><div class="tscroll"><table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.map((c, i) => `<td${i ? ' class="num"' : ''}>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div></details>`;
}

// 1. One measure across seven categories: horizontal bars, direct labels.
function categoryChart(S) {
  const total = S.toolCalls || 1;
  const max = Math.max(1, ...CATEGORIES.map((c) => S.categories[c.id] || 0));
  const W = 760, L = 150, R = 110, rowH = 30, barH = 18;
  const H = CATEGORIES.length * rowH + 8;
  const scale = (v) => ((W - L - R) * v) / max;
  const rows = CATEGORIES.map((c, i) => {
    const v = S.categories[c.id] || 0;
    const y = 4 + i * rowH;
    const tip = `${c.label}: ${n(v)} calls (${pct(v, total)})`;
    return `<g class="mark" data-tip="${esc(tip)}" tabindex="0">
      <rect x="0" y="${y}" width="${W}" height="${rowH}" fill="transparent"/>
      <text x="${L - 12}" y="${y + barH / 2 + 5}" text-anchor="end" class="lbl">${esc(c.label)}</text>
      <path d="${hbar(L, y + (rowH - barH) / 2 - 2, scale(v), barH)}" fill="${catVar(i)}"/>
      <text x="${L + scale(v) + 8}" y="${y + barH / 2 + 5}" class="val">${esc(n(v))} · ${esc(pct(v, total))}</text>
    </g>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Tool calls by category">${rows}</svg>
    ${table(['Category', 'Calls', 'Share'], CATEGORIES.map((c) => [c.label, n(S.categories[c.id]), pct(S.categories[c.id] || 0, total)]))}`;
}

// 2. Projects x categories. Projects differ in size by orders of magnitude,
// so each bar shows its own composition (100%) and the total is a number:
// a shared scale would turn small projects into unreadable slivers.
function projectChart(S) {
  const list = Object.entries(S.projects).sort((a, b) => b[1].toolCalls - a[1].toolCalls).slice(0, 12);
  if (!list.length) return '<p class="muted">No projects.</p>';
  const W = 760, L = 190, R = 150, rowH = 32, barH = 18, gap = 2;
  const H = list.length * rowH + 8;
  const span = W - L - R;
  const rows = list.map(([name, p], i) => {
    const y = 4 + i * rowH + (rowH - barH) / 2;
    const total = p.toolCalls || 0;
    const present = CATEGORIES.map((c, ci) => ({ c, ci, v: (p.categories && p.categories[c.id]) || 0 })).filter((s) => s.v > 0);
    const usable = span - gap * Math.max(0, present.length - 1);
    let x = L;
    const segs = present.map((s, k) => {
      const w = Math.max((usable * s.v) / (total || 1), 1.5);
      const last = k === present.length - 1;
      const d = last ? hbar(x, y, Math.max(L + span - x, 1.5), barH) : `M${x} ${y}h${w}v${barH}h-${w}z`;
      const tip = `${name} · ${s.c.label}: ${n(s.v)} of ${n(total)} calls (${pct(s.v, total)})`;
      const el = `<path class="mark seg" d="${d}" fill="${catVar(s.ci)}" data-tip="${esc(tip)}" tabindex="0"/>`;
      x += w + gap;
      return el;
    }).join('');
    const label = name.length > 26 ? name.slice(0, 25) + '…' : name;
    return `<text x="${L - 12}" y="${y + barH / 2 + 5}" text-anchor="end" class="lbl">${esc(label)}</text>${segs}
      <text x="${L + span + 10}" y="${y + barH / 2 + 5}" class="val">${esc(n(total))} calls${p.flagged ? ` <tspan class="flag">· ${esc(p.flagged)} flagged</tspan>` : ''}</text>`;
  }).join('');
  return `${legend()}<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Share of tool calls by category for each project">${rows}</svg>
    ${table(['Project', 'Sessions', 'Calls', 'Flagged', ...CATEGORIES.map((c) => c.label)],
      list.map(([name, p]) => [name, p.sessions, n(p.toolCalls), p.flagged, ...CATEGORIES.map((c) => n((p.categories || {})[c.id]))]))}`;
}

// 3. Calls per day, stacked by category; every day in the range gets a slot.
function dayChart(S) {
  if (!S.daily || !S.daily.length) return '<p class="muted">No dated activity.</p>';
  const byDate = Object.fromEntries(S.daily.map((d) => [d.date, d]));
  const start = Date.parse(S.daily[0].date), end = Date.parse(S.daily[S.daily.length - 1].date);
  const dates = [];
  for (let t = start; t <= end; t += 864e5) dates.push(new Date(t).toISOString().slice(0, 10));
  const totals = dates.map((d) => CATEGORIES.reduce((a, c) => a + ((byDate[d] || {})[c.id] || 0), 0));
  const max = Math.max(1, ...totals);
  // ~4 gridlines at a 1/2/5 x 10^k step; the top tick is the first one >= max
  const raw = max / 4;
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(raw, 1))));
  const step = Math.max(1, [1, 2, 5, 10].map((m) => m * mag).find((v) => v >= raw) ?? 10 * mag);
  const top = Math.ceil(max / step) * step;
  const ticks = [];
  for (let v = 0; v <= top; v += step) ticks.push(v);
  const W = 760, L = 44, R = 12, T = 10, B = 34, H = 240;
  const plotW = W - L - R, plotH = H - T - B;
  const slot = plotW / dates.length;
  const bw = Math.max(Math.min(slot - 4, 28), 2);
  const y = (v) => T + plotH - (plotH * v) / top;
  const grid = ticks.map((v) => `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end" class="tick">${esc(n(v))}</text>`).join('');
  const every = Math.ceil(dates.length / 8);
  const cols = dates.map((d, i) => {
    const x = L + i * slot + (slot - bw) / 2;
    const day = byDate[d] || {};
    let base = T + plotH;
    const present = CATEGORIES.map((c, ci) => ({ c, ci, v: day[c.id] || 0 })).filter((s) => s.v > 0);
    const segs = present.map((s, k) => {
      const h = Math.max((plotH * s.v) / top - (k < present.length - 1 ? 2 : 0), 1);
      const last = k === present.length - 1;
      const dpath = last ? vbar(x, base, bw, h) : `M${x} ${base}v-${h}h${bw}v${h}z`;
      const el = `<path d="${dpath}" fill="${catVar(s.ci)}"/>`;
      base -= h + 2;
      return el;
    }).join('');
    const tip = `${d}: ${n(totals[i])} calls` + (present.length ? ' · ' + present.map((s) => `${s.c.label} ${n(s.v)}`).join(', ') : '');
    const label = i % every === 0 ? `<text x="${x + bw / 2}" y="${H - 12}" text-anchor="middle" class="tick">${esc(d.slice(5))}</text>` : '';
    return `<g class="mark" data-tip="${esc(tip)}" tabindex="0"><rect x="${L + i * slot}" y="${T}" width="${slot}" height="${plotH}" fill="transparent"/>${segs}</g>${label}`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Tool calls per day by category">${grid}<line x1="${L}" x2="${W - R}" y1="${T + plotH}" y2="${T + plotH}" class="axis"/>${cols}</svg>
    ${table(['Date', 'Total', ...CATEGORIES.map((c) => c.label)], dates.map((d, i) => [d, n(totals[i]), ...CATEGORIES.map((c) => n((byDate[d] || {})[c.id]))]))}`;
}

/**
 * Ranked lists: name, inline bar, count. Bars share one neutral ink.
 * @param {{ name: string, count: number, tag?: string, tagClass?: string }[]} rows
 * @param {{ dot?: (row: any) => string }} [opts]
 */
function ranked(rows, { dot } = {}) {
  if (!rows.length) return '<p class="muted">None.</p>';
  const max = Math.max(1, ...rows.map((r) => r.count));
  return `<table class="ranked"><tbody>${rows.map((r) => `<tr>
    <td class="name">${dot != null ? `<span class="sw" style="background:${dot(r)}"></span>` : ''}${esc(r.name)}${r.tag ? ` <span class="tag tag-${esc(r.tagClass || '')}">${esc(r.tag)}</span>` : ''}</td>
    <td class="barcell"><span class="ibar" style="width:${((r.count / max) * 100).toFixed(1)}%"></span></td>
    <td class="num">${esc(n(r.count))}</td></tr>`).join('')}</tbody></table>`;
}

function skillsTable(S) {
  const rows = S.skills || [];
  if (!rows.length) return '<p class="muted">No skills used in this period.</p>';
  const max = Math.max(1, ...rows.map((r) => r.calls));
  const riskTag = (r) => (r.risk == null ? '<span class="tag">not installed here</span>'
    : r.risk === 'high' ? '<span class="rule rule-bad">high risk</span>' : r.risk === 'medium' ? '<span class="rule rule-warn">medium risk</span>'
      : '<span class="tag tag-ok">clean</span>');
  return `<div class="tscroll"><table><thead><tr><th>Skill</th><th></th><th class="num">Calls</th><th class="num">Model / you</th><th>Audit</th><th>Findings</th></tr></thead><tbody>${rows.map((r) => `<tr>
    <td class="name">${esc(r.name)}${r.source ? ` <span class="muted">· ${esc(r.source)}</span>` : ''}</td>
    <td class="barcell"><span class="ibar" style="width:${((r.calls / max) * 100).toFixed(1)}%"></span></td>
    <td class="num">${esc(n(r.calls))}</td><td class="num">${esc(r.byModel)} / ${esc(r.byUser)}</td>
    <td>${riskTag(r)}${r.pin === 'changed' ? ' <span class="rule rule-bad">changed since pin</span>' : ''}</td>
    <td class="reason">${esc((r.rules || []).join(', '))}</td></tr>`).join('')}</tbody></table></div>`;
}

function mcpTable(S) {
  const used = (S.mcp && S.mcp.used) || [];
  const unused = (S.mcp && S.mcp.unused) || [];
  if (!used.length && !unused.length) return '<p class="muted">No MCP servers used or configured.</p>';
  const max = Math.max(1, ...used.map((m) => m.calls));
  const riskTag = (r) => (r === 'high' ? '<span class="rule rule-bad">high risk</span>' : r === 'medium' ? '<span class="rule rule-warn">medium risk</span>' : r ? '<span class="tag tag-ok">clean</span>' : '');
  const rows = used.map((m) => {
    const worst = (m.configured || []).sort((a, b) => ({ high: 3, medium: 2, low: 1, none: 0 }[b.risk] - { high: 3, medium: 2, low: 1, none: 0 }[a.risk]))[0];
    const where = (m.configured || []).length ? m.configured.map((c) => `${c.client} ${c.scope}`).join(', ') : 'connector / managed';
    const tools = m.tools.slice(0, 5).map((t) => `${esc(t.name)}${t.outbound ? ' ↗' : ''} <span class="muted">${esc(n(t.calls))}</span>`).join(' · ');
    return `<tr><td class="name">${esc(m.server)}${m.plugin ? ` <span class="muted">· plugin ${esc(m.plugin)}</span>` : ''}<div class="muted" style="font-size:11.5px">${esc(where)}</div></td>
      <td class="barcell"><span class="ibar" style="width:${((m.calls / max) * 100).toFixed(1)}%"></span></td>
      <td class="num">${esc(n(m.calls))}</td><td class="num">${m.outboundCalls ? `<span class="rule rule-warn">${esc(n(m.outboundCalls))} ↗</span>` : '<span class="muted">read-only</span>'}</td>
      <td class="num">${m.errors ? `<span class="rule rule-bad">${esc(n(m.errors))}</span>` : '<span class="muted">0</span>'}</td>
      <td>${worst ? riskTag(worst.risk) : '<span class="tag">not local</span>'}${worst && worst.rules.length ? `<div class="reason" style="font-size:11.5px">${esc(worst.rules.join(', '))}</div>` : ''}</td>
      <td class="reason" style="font-size:12px">${tools}</td></tr>`;
  }).join('');
  const unusedRows = unused.map((u) => `<tr><td class="name">${esc(u.server)}<div class="muted" style="font-size:11.5px">${esc(u.client)} ${esc(u.scope)}</div></td><td></td><td class="num muted">0</td><td></td><td></td><td>${riskTag(u.risk)}${u.rules.length ? `<div class="reason" style="font-size:11.5px">${esc(u.rules.join(', '))}</div>` : ''}</td><td class="muted">configured, not used: candidate to remove</td></tr>`).join('');
  return `<div class="tscroll"><table><thead><tr><th>Server</th><th></th><th class="num">Calls</th><th class="num">Sent / changed</th><th class="num">Failed</th><th>Config audit</th><th>Tools</th></tr></thead><tbody>${rows}${unusedRows}</tbody></table></div>`;
}

function renderHtml(S) {
  const range = S.range && S.range.first ? `${String(S.range.first).slice(0, 10)} → ${String(S.range.last).slice(0, 10)}` : `last ${S.days} days`;
  const catIndex = Object.fromEntries(CATEGORIES.map((c, i) => [c.id, i]));
  const tiles = [
    ['Sessions', S.sessions, ''], ['Tool calls', S.toolCalls, ''],
    ['Sessions that read private data', S.privateSessions, 'warn'], ['Outbound calls', S.outboundCalls, 'warn'],
    ['Lethal-trifecta sessions', S.trifectaSessions, 'bad'], ['Calls that would be denied', S.wouldDenyCalls, 'bad'],
  ];
  const flagged = (S.flagged || []).map((f) => `<tr><td>${esc(String(f.date || '').slice(0, 10))}</td><td>${esc(f.project || '')}</td><td><span class="rule rule-${/egress/.test(f.rule) && f.rule !== 'lethal-trifecta' ? 'bad' : 'warn'}">${esc(f.rule)}</span></td><td class="reason">${esc(f.reason || '')}</td></tr>`).join('');
  const hostKind = { allowlisted: 'ok', 'named by you': 'ok', external: 'warn' };
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent activity report</title>
<style>
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--ink-3:#77766f;--line:#e4e3de;--grid:#ecebe7;--axis:#c9c8c1;
--series-1:#2a78d6;--series-2:#eb6834;--series-3:#1baf7a;--series-4:#eda100;--series-5:#e87ba4;--series-6:#008300;--series-7:#4a3aa7;
--warn:#a35f00;--warn-bg:#fdf3e1;--bad:#b42f2f;--bad-bg:#fbeaea;--ok:#2f6b2f;--ok-bg:#e8f3e8;--ibar:#9a9890}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#121211;--surface:#1a1a19;--ink:#fff;--ink-2:#c3c2b7;--ink-3:#97968d;--line:#2f2f2c;--grid:#262624;--axis:#45453f;
--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--series-4:#c98500;--series-5:#d55181;--series-6:#008300;--series-7:#9085e9;
--warn:#f0b04a;--warn-bg:#33270f;--bad:#ff8a7a;--bad-bg:#3a1c18;--ok:#8fd18f;--ok-bg:#1c2e1c;--ibar:#6f6e66}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#121211;--surface:#1a1a19;--ink:#fff;--ink-2:#c3c2b7;--ink-3:#97968d;--line:#2f2f2c;--grid:#262624;--axis:#45453f;
--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--series-4:#c98500;--series-5:#d55181;--series-6:#008300;--series-7:#9085e9;
--warn:#f0b04a;--warn-bg:#33270f;--bad:#ff8a7a;--bad-bg:#3a1c18;--ok:#8fd18f;--ok-bg:#1c2e1c;--ibar:#6f6e66}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 64px}
header h1{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}header p{margin:0;color:var(--ink-2)}
.note{margin:12px 0 0;font-size:12.5px;color:var(--ink-3)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:30px;line-height:1.1;font-variant-numeric:tabular-nums}.tile span{color:var(--ink-2);font-size:12.5px}
.tile.warn b{color:var(--warn)}.tile.bad b{color:var(--bad)}
section{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:14px 0}
section h2{font-size:15px;margin:0 0 2px}section .sub{color:var(--ink-2);font-size:12.5px;margin:0 0 12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.grid2 section{margin:0}
svg{width:100%;height:auto;display:block;overflow:visible}
svg text{font-family:inherit}.lbl{fill:var(--ink-2);font-size:12.5px}.val{fill:var(--ink);font-size:12.5px;font-variant-numeric:tabular-nums}.tick{fill:var(--ink-3);font-size:11px}
.flag{fill:var(--bad)}.grid{stroke:var(--grid);stroke-width:1}.axis{stroke:var(--axis);stroke-width:1}
.mark:focus{outline:none}.mark:focus-visible path,.mark:focus-visible{stroke:var(--ink);stroke-width:1.5}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;list-style:none;padding:0;margin:0 0 10px;font-size:12.5px;color:var(--ink-2)}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
details.data{margin-top:10px;font-size:12.5px}details.data summary{cursor:pointer;color:var(--ink-2)}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{text-align:left;color:var(--ink-2);font-weight:600;border-bottom:1px solid var(--line);padding:6px 8px}
td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.ranked td{border:0;padding:4px 6px}.ranked .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
.barcell{width:45%}.ibar{display:block;height:8px;border-radius:0 4px 4px 0;background:var(--ibar);min-width:2px}
.tag{font-size:11px;padding:1px 6px;border-radius:4px}.tag-ok{background:var(--ok-bg);color:var(--ok)}.tag-warn{background:var(--warn-bg);color:var(--warn)}
.rule{font-size:11.5px;padding:1px 6px;border-radius:4px;white-space:nowrap}.rule-warn{background:var(--warn-bg);color:var(--warn)}.rule-bad{background:var(--bad-bg);color:var(--bad)}
.reason{color:var(--ink-2);min-width:220px}.tscroll{overflow-x:auto}.muted{color:var(--ink-3)}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:6px 9px;border-radius:6px;max-width:320px;opacity:0;transition:opacity .08s;z-index:9}
footer{color:var(--ink-3);font-size:12px;margin-top:24px;text-align:center}
@media (max-width:720px){.grid2{grid-template-columns:1fr}}
</style></head>
<body><main>
<header><h1>What your AI coding agent did</h1><p>Claude Code · ${esc(range)} · ${esc(n(S.sessions))} sessions · ${esc(n(S.toolCalls))} tool calls</p>
<p class="note">Built locally by agent-blackbox from your session history. Contains project, program and host names, never commands, prompts or secrets. For public sharing use <code>blackbox scan --card</code>.</p></header>
<div class="tiles">${tiles.map(([l, v, c]) => `<div class="tile ${c}"><b>${esc(n(v))}</b><span>${esc(l)}</span></div>`).join('')}</div>
<section><h2>Tool calls by category</h2><p class="sub">What kind of work the agent did.</p>${categoryChart(S)}</section>
<section><h2>Projects</h2><p class="sub">What each project's calls were made of. Bars show shares; the total is on the right. Hover a segment for the count.</p>${projectChart(S)}</section>
<section><h2>Activity per day</h2><p class="sub">Calls per day, split by category.</p>${legend()}${dayChart(S)}</section>
<div class="grid2">
<section><h2>Top tools</h2><p class="sub">Colored by category.</p>${ranked((S.topTools || []).map((t) => ({ name: t.name, count: t.count, cat: t.category })), { dot: (r) => catVar(catIndex[r.cat] ?? 6) })}</section>
<section><h2>Shell programs</h2><p class="sub">First program of each command segment.</p>${ranked((S.shellPrograms || []).map((p) => ({ name: p.name, count: p.count })))}</section>
</div>
<section><h2>Skills</h2><p class="sub">Skills the agent loaded (model) or you invoked with a slash command (you), with the result of the local audit (<code>blackbox skills</code>).</p>${skillsTable(S)}</section>
<section><h2>MCP servers</h2><p class="sub">Servers the agent called, the tools it used (↗ sends or changes data), and where each server is configured, with the local config audit (<code>blackbox mcp</code>).</p>${mcpTable(S)}</section>
<section><h2>Network destinations</h2><p class="sub">Hosts in WebFetch URLs and shell commands. "External" hosts are neither allowlisted nor named by you in a prompt.</p>${ranked((S.hosts || []).map((h) => ({ name: h.host, count: h.calls, tag: h.kind, tagClass: hostKind[h.kind] || 'warn' })))}</section>
<section><h2>Flagged events</h2><p class="sub">What the firewall would have stopped or asked about.</p>${flagged ? `<div class="tscroll"><table><thead><tr><th>Date</th><th>Project</th><th>Rule</th><th>Reason</th></tr></thead><tbody>${flagged}</tbody></table></div>` : '<p class="muted">Nothing flagged.</p>'}</section>
<footer>agent-blackbox · scanned locally, nothing uploaded</footer>
</main><div id="tip" role="tooltip"></div>
<script>
(function(){var tip=document.getElementById('tip');function show(el,x,y){tip.textContent=el.getAttribute('data-tip');tip.style.opacity=1;var w=tip.offsetWidth,h=tip.offsetHeight;tip.style.left=Math.min(x+14,innerWidth-w-8)+'px';tip.style.top=Math.max(y-h-10,8)+'px';}
function hide(){tip.style.opacity=0;}
document.querySelectorAll('[data-tip]').forEach(function(el){el.addEventListener('mousemove',function(e){show(el,e.clientX,e.clientY);});el.addEventListener('mouseleave',hide);
el.addEventListener('focus',function(){var r=el.getBoundingClientRect();show(el,r.left+r.width/2,r.top);});el.addEventListener('blur',hide);});})();
</script>
</body></html>
`;
}

module.exports = { renderHtml };
