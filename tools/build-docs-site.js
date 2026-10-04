#!/usr/bin/env node
// Renders selected repo docs to static pages under site/docs/ so they can be indexed
// and linked. Small Markdown subset (headings, paragraphs, lists, tables, code, links,
// bold, italic, inline code). No dependencies. Re-run after editing a source doc; it
// also rewrites site/sitemap.xml.
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const BASE = 'https://developerfred.github.io/agent-blackbox/';
const GH = 'https://github.com/developerfred/agent-blackbox/blob/main/';

const PAGES = [
  { src: 'docs/PRIVACY.md', out: 'privacy', title: 'Privacy: what agent-blackbox records and keeps', desc: 'What the agent-blackbox recorder stores, where, for how long, how crypto-erase works and what the defaults do not protect against.' },
  { src: 'docs/AGENT-GUIDE.md', out: 'agent-guide', title: 'Agent guide: using agent-blackbox from an AI coding agent', desc: 'What a coding agent should do when a tool call is blocked, which commands are safe to run and how to install the recorder for a person.' },
  { src: 'docs/AGENT-API.md', out: 'agent-api', title: 'Agent API: read-only JSON endpoints for AI agents', desc: 'Versioned, read-only /v1/agent endpoints with OpenAPI that let an agent read what agent-blackbox recorded.' },
  { src: 'docs/spec/ledger-v1.md', out: 'ledger-spec', title: 'Ledger format v1: an open, hash-chained audit log for AI agents', desc: 'The open ledger and event format used by agent-blackbox: hash chain, Ed25519 signatures, sealed payloads, crypto-erase and Merkle anchors.' },
  { src: 'docs/ANCHORING.md', out: 'anchoring', title: 'Anchoring: Merkle roots and inclusion proofs for the audit log', desc: 'How agent-blackbox commits to batches of ledger records with an RFC 6962 Merkle root and how to prove one record belongs to it.' },
  { src: 'docs/OTEL.md', out: 'opentelemetry-export', title: 'OpenTelemetry GenAI export for AI agent audit logs', desc: 'blackbox export writes the ledger as OTLP/JSON traces and logs following the OpenTelemetry GenAI conventions, metadata only.' },
  { src: 'docs/AGENTS.md', out: 'agents-supported', title: 'Supported agents: Claude Code, Codex CLI, Cursor, Gemini CLI', desc: 'How agent-blackbox records and gates Claude Code, Codex CLI, Cursor and Gemini CLI, and what each adapter does not cover.' },
];
const known = new Map(PAGES.map((p) => [path.normalize(p.src), p.out]));

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function link(srcFile, href) {
  if (/^(https?:|mailto:|#)/.test(href)) return href;
  const [file, hash] = href.split('#');
  const abs = path.normalize(path.join(path.dirname(srcFile), file));
  if (known.has(abs)) return `${known.get(abs)}.html${hash ? '#' + hash : ''}`;
  return GH + abs.split(path.sep).join('/') + (hash ? '#' + hash : '');
}
function inline(srcFile, t) {
  const codes = [];
  t = t.replace(/`([^`]+)`/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
  t = esc(t);
  t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, href) => `<a href="${link(srcFile, href.replace(/&amp;/g, '&'))}">${text}</a>`);
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
  return t.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(codes[+i])}</code>`);
}
const slug = (s) => s.toLowerCase().replace(/<[^>]+>/g, '').replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-');

function render(srcFile, md) {
  const lines = md.replace(/\r/g, '').split('\n');
  const out = [];
  let i = 0;
  let title = '';
  while (i < lines.length) {
    const l = lines[i];
    if (/^```/.test(l)) {
      const buf = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++; out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`); continue;
    }
    const h = l.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const n = h[1].length;
      if (n === 1 && !title) { title = h[2]; i++; continue; }
      out.push(`<h${n}${n > 1 ? ` id="${slug(h[2])}"` : ''}>${inline(srcFile, h[2])}</h${n}>`); i++; continue;
    }
    if (/^\|.*\|\s*$/.test(l) && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1] || '')) {
      const cells = (r) => r.replace(/^\||\|\s*$/g, '').split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
      const head = cells(l); i += 2; const rows = [];
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(`<div class="tablewrap"><table><tr>${head.map((c) => `<th>${inline(srcFile, c)}</th>`).join('')}</tr>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(srcFile, c)}</td>`).join('')}</tr>`).join('')}</table></div>`);
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l); const items = [];
      while (i < lines.length && (/^\s*([-*]|\d+\.)\s+/.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
        if (/^\s*([-*]|\d+\.)\s+/.test(lines[i])) items.push(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ''));
        else items[items.length - 1] += ' ' + lines[i].trim();
        i++;
      }
      out.push(`<${ordered ? 'ol' : 'ul'} class="plain">${items.map((t) => `<li>${inline(srcFile, t)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`); continue;
    }
    if (/^>\s?/.test(l)) {
      const buf = []; while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
      out.push(`<blockquote>${inline(srcFile, buf.join(' '))}</blockquote>`); continue;
    }
    if (!l.trim()) { i++; continue; }
    const buf = [];
    while (i < lines.length && lines[i].trim() && !/^(```|#{1,4}\s|\s*([-*]|\d+\.)\s+|>|\|.*\|\s*$)/.test(lines[i])) buf.push(lines[i++]);
    if (!buf.length) { buf.push(lines[i++]); }
    out.push(`<p>${inline(srcFile, buf.join(' '))}</p>`);
  }
  return { title, html: out.join('\n') };
}

const nav = PAGES.map((p) => `<a href="${p.out}.html">${esc(p.out.replace(/-/g, ' '))}</a>`).join('');
fs.mkdirSync(path.join(root, 'site', 'docs'), { recursive: true });
for (const p of PAGES) {
  const { title, html } = render(p.src, fs.readFileSync(path.join(root, p.src), 'utf8'));
  const url = `${BASE}docs/${p.out}.html`;
  const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.title)}</title>
<meta name="description" content="${esc(p.desc)}">
<link rel="canonical" href="${url}">
<meta name="theme-color" content="#0f1113">
<meta property="og:type" content="article">
<meta property="og:site_name" content="agent-blackbox">
<meta property="og:title" content="${esc(p.title)}">
<meta property="og:description" content="${esc(p.desc)}">
<meta property="og:url" content="${url}">
<meta property="og:image" content="${BASE}media/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(p.title)}">
<meta name="twitter:description" content="${esc(p.desc)}">
<meta name="twitter:image" content="${BASE}media/og.png">
<link rel="stylesheet" href="../style.css">
<style>.doc{max-width:760px;margin:0 auto;padding-block:40px 24px}.doc h1{margin-bottom:18px}.doc h2{margin-top:36px}.doc h3{margin-top:26px;font-size:1.15rem}.doc ul.plain,.doc ol.plain{margin:0 0 14px;padding-left:1.3em}.doc blockquote{margin:0 0 14px;padding:2px 16px;border-left:3px solid var(--accent);color:var(--muted)}.doc .tablewrap{margin:0 0 16px}.doc pre{margin:0 0 16px}.docnav{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.85rem;padding-block:12px;border-bottom:1px solid var(--line)}.docnav a{color:var(--muted);text-decoration:none}.docnav a:hover{color:var(--fg)}</style>
</head>
<body>
<header class="top"><div class="wrap"><nav>
<strong><a href="../index.html" style="color:inherit;text-decoration:none">agent-blackbox</a></strong>
<a href="../index.html#install">Install</a><a href="../index.html#policy">Policy</a><a href="https://github.com/developerfred/agent-blackbox">GitHub</a>
</nav></div></header>
<div class="wrap"><div class="docnav">${nav}</div>
<main class="doc">
<h1>${esc(title)}</h1>
${html}
<p style="margin-top:32px"><a href="${GH}${p.src}">Edit this page on GitHub</a></p>
</main></div>
<footer><div class="wrap">Apache-2.0 · <a href="https://github.com/developerfred/agent-blackbox">source</a> · This page loads no scripts, fonts or trackers.</div></footer>
</body>
</html>
`;
  fs.writeFileSync(path.join(root, 'site', 'docs', `${p.out}.html`), page);
}

const alt = (loc) => `<xhtml:link rel="alternate" hreflang="en" href="${BASE}"/><xhtml:link rel="alternate" hreflang="pt-BR" href="${BASE}pt.html"/>`;
const urls = [`<url><loc>${BASE}</loc>${alt()}</url>`, `<url><loc>${BASE}pt.html</loc>${alt()}</url>`,
  ...PAGES.map((p) => `<url><loc>${BASE}docs/${p.out}.html</loc></url>`)];
fs.writeFileSync(path.join(root, 'site', 'sitemap.xml'),
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${urls.join('\n')}\n</urlset>\n`);
console.log(`wrote ${PAGES.length} docs pages and the sitemap`);
