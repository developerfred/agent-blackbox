'use strict';
// Terminal view of `blackbox mcp`: configured servers joined with real usage.
const SEV = { high: 3, medium: 2, low: 1, none: 0 };

function renderMcp(audits, summary, { color = false, all = false } = {}) {
  const c = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const red = c(31), yellow = c(33), green = c(32), dim = c(2), bold = c(1), cyan = c(36);
  const n = (x) => Number(x || 0).toLocaleString('en-US');
  const used = (summary.mcp && summary.mcp.used) || [];
  const out = [bold(`agent-blackbox mcp · ${used.length} servers used in the last ${summary.days} days · ${audits.length} configured`)];
  const riskTag = (r) => (r === 'high' ? red('high risk') : r === 'medium' ? yellow('medium risk') : r === 'low' ? dim('low') : green('clean'));
  const defLine = (a) => (a.command ? `${a.transport} · ${[a.command, ...a.args].join(' ')}` : `${a.transport} · ${a.url || ''}`);
  const findingsOf = (a) => a.findings.filter((f) => all || f.severity !== 'low');

  if (used.length) {
    out.push('');
    out.push(bold('  used') + dim('   (↗ = tool that sends or changes data)'));
    for (const m of used) {
      const cfgs = audits.filter((a) => a.name.toLowerCase().replace(/[^a-z0-9]+/g, '_') === m.server.toLowerCase().replace(/[^a-z0-9]+/g, '_'));
      const worst = cfgs.sort((a, b) => SEV[b.risk] - SEV[a.risk])[0];
      out.push(`  ${bold(m.server)}${m.plugin ? dim(` (plugin ${m.plugin})`) : ''}  ${worst ? riskTag(worst.risk) : dim('not in a local config: claude.ai connector, managed or removed')}`);
      out.push(`      ${n(m.calls)} calls · ${n(m.sessions)} sessions · last ${String(m.lastUsed || '').slice(0, 10)}${m.outboundCalls ? ' · ' + yellow(`${n(m.outboundCalls)} sent or changed data`) : ' · ' + dim('read-only')}${m.errors ? ' · ' + red(`${n(m.errors)} failed`) : ''}`);
      out.push(dim(`      tools: ${m.tools.slice(0, 8).map((t) => `${t.name}${t.outbound ? '↗' : ''} ${t.calls}`).join(' · ')}${m.tools.length > 8 ? ` · +${m.tools.length - 8} more` : ''}`));
      for (const a of cfgs) {
        out.push(dim(`      ${a.client} ${a.scope} · ${defLine(a).slice(0, 110)}`));
        for (const f of findingsOf(a)) out.push(`        ${f.severity === 'high' ? red('•') : f.severity === 'medium' ? yellow('•') : dim('•')} ${f.rule}: ${f.message}${f.detail ? dim(`  [${f.detail}]`) : ''}`);
      }
    }
  } else {
    out.push(dim('  no MCP tool calls in this period'));
  }
  const unused = (summary.mcp && summary.mcp.unused) || [];
  if (unused.length) {
    out.push('');
    out.push(bold('  configured but not used in this period') + dim('   (candidates to remove: less attack surface)'));
    for (const u of unused) {
      const a = audits.find((x) => x.name === u.server && x.client === u.client && x.scope === u.scope);
      out.push(`  ${u.server.padEnd(28)} ${dim(`${u.client} ${u.scope}`.padEnd(24))} ${riskTag(u.risk)}  ${dim(a ? defLine(a).slice(0, 70) : '')}`);
      if (a) for (const f of findingsOf(a)) out.push(`        ${f.severity === 'high' ? red('•') : f.severity === 'medium' ? yellow('•') : dim('•')} ${f.rule}: ${f.message}${f.detail ? dim(`  [${f.detail}]`) : ''}`);
    }
  }
  out.push('');
  out.push(dim('  Configs read: Claude Code (~/.claude.json, .mcp.json, plugins), Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf, Copilot CLI.'));
  if (audits.some((a) => a.pin !== 'pinned')) out.push(`  Record today's definitions so later changes are flagged: ${cyan('blackbox mcp --pin')}`);
  return out.join('\n');
}

module.exports = { renderMcp };
