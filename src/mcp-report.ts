// Terminal view of `blackbox mcp`: configured servers joined with real usage.
import { palette } from './term';
import { configFor } from './mcp';
import type { McpAudit, Finding } from './types';

interface McpTool { name: string; calls: number; outbound?: boolean }

const SEV: Record<string, number> = { high: 3, medium: 2, low: 1, none: 0 };

/** `summary` is the result of scan() with the mcp section. */
export function renderMcp(audits: McpAudit[], summary: any, { color = false, all = false }: { color?: boolean; all?: boolean } = {}): string {
  const { red, yellow, green, dim, bold, cyan, bySeverity } = palette(color);
  const n = (x: unknown): string => Number(x || 0).toLocaleString('en-US');
  const used = (summary.mcp && summary.mcp.used) || [];
  const out = [bold(`agent-blackbox mcp · ${used.length} servers used in the last ${summary.days} days · ${audits.length} configured`)];
  const riskTag = (r: string): string => (r === 'high' ? red('high risk') : r === 'medium' ? yellow('medium risk') : r === 'low' ? dim('low') : green('clean'));
  const defLine = (a: McpAudit): string => (a.command ? `${a.transport} · ${[a.command, ...a.args].join(' ')}` : `${a.transport} · ${a.url || ''}`);
  const findingsOf = (a: McpAudit): Finding[] => a.findings.filter((f) => all || f.severity !== 'low');
  const findingLine = (f: Finding): string => `        ${bySeverity[f.severity]('•')} ${f.rule}: ${f.message}${f.detail ? dim(`  [${f.detail}]`) : ''}`;

  if (used.length) {
    out.push('');
    out.push(bold('  used') + dim('   (↗ = tool that sends or changes data)'));
    for (const m of used) {
      const cfgs = configFor(audits, m.server);
      const worst = cfgs.sort((a, b) => SEV[b.risk] - SEV[a.risk])[0];
      out.push(`  ${bold(m.server)}${m.plugin ? dim(` (plugin ${m.plugin})`) : ''}  ${worst ? riskTag(worst.risk) : dim('not in a local config: claude.ai connector, managed or removed')}`);
      out.push(`      ${n(m.calls)} ${m.calls === 1 ? "call" : "calls"} · ${n(m.sessions)} ${m.sessions === 1 ? "session" : "sessions"} · last ${String(m.lastUsed || '').slice(0, 10)}${m.outboundCalls ? ' · ' + yellow(`${n(m.outboundCalls)} sent or changed data`) : ' · ' + dim('read-only')}${m.errors ? ' · ' + red(`${n(m.errors)} failed`) : ''}`);
      out.push(dim(`      tools: ${m.tools.slice(0, 8).map((t: McpTool) => `${t.name}${t.outbound ? '↗' : ''} ${t.calls}`).join(' · ')}${m.tools.length > 8 ? ` · +${m.tools.length - 8} more` : ''}`));
      for (const a of cfgs) {
        out.push(dim(`      ${a.client} ${a.scope} · ${defLine(a).slice(0, 110)}`));
        for (const f of findingsOf(a)) out.push(findingLine(f));
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
      if (a) for (const f of findingsOf(a)) out.push(findingLine(f));
    }
  }
  out.push('');
  out.push(dim('  Configs read: Claude Code (~/.claude.json, .mcp.json, plugins), Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf, Copilot CLI.'));
  if (audits.some((a) => a.pin !== 'pinned')) out.push(`  Record today's definitions so later changes are flagged: ${cyan('blackbox mcp --pin')}`);
  return out.join('\n');
}
