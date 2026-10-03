'use strict';
// Synthetic audits for the terminal reports. Hosts and names are placeholders.
const mkAudit = (o) => ({ name: 'github', client: 'claude-code', scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', '@x/server'], url: null, findings: [], counts: { high: 0, medium: 0, low: 0 }, risk: 'none', pin: 'pinned', ...o });
const mcpAudits = [
  mkAudit({ name: 'github', risk: 'high', counts: { high: 1, medium: 0, low: 1 }, pin: 'new', findings: [{ severity: 'high', rule: 'secret-in-config', message: 'clear-text token', detail: 'GITHUB_TOKEN' }, { severity: 'low', rule: 'unpinned-version', message: 'no version pin', detail: null }] }),
  mkAudit({ name: 'files', client: 'cursor', scope: 'project', transport: 'http', command: null, args: [], url: 'http://localhost:9000/mcp', risk: 'medium', findings: [{ severity: 'medium', rule: 'plain-http', message: 'uses http', detail: null }] }),
  mkAudit({ name: 'old', risk: 'low', findings: [] }),
];
const summary = { days: 30, mcp: {
  used: [{ server: 'github', plugin: null, calls: 12, sessions: 3, outboundCalls: 2, errors: 1, lastUsed: '2026-09-20T10:00:00Z', tools: [{ name: 'create_issue', calls: 2, outbound: true }, { name: 'list', calls: 10, outbound: false }] },
         { server: 'ghost', plugin: 'p', calls: 1, sessions: 1, outboundCalls: 0, errors: 0, lastUsed: '2026-09-21T10:00:00Z', tools: [] }],
  unused: [{ server: 'files', client: 'cursor', scope: 'project', risk: 'medium' }, { server: 'old', client: 'claude-code', scope: 'user', risk: 'low' }] } };
const skillAudit = (o) => ({ name: 'deploy', source: 'claude personal', fileCount: 3, risk: 'none', counts: { high: 0, medium: 0, low: 0 }, pin: { status: 'pinned' }, findings: [], ...o });
const skills = [
  skillAudit({ name: 'zeta', risk: 'high', counts: { high: 1, medium: 1, low: 1 }, pin: { status: 'changed' }, findings: [{ severity: 'high', rule: 'curl-pipe-shell', file: 'SKILL.md', line: 4, message: 'pipes a download into a shell', excerpt: 'curl x | sh' }, { severity: 'low', rule: 'note', file: 'a.md', line: 0, message: 'minor' }] }),
  skillAudit({ name: 'alpha', risk: 'none' }),
  skillAudit({ name: 'beta', risk: 'medium', counts: { high: 0, medium: 2, low: 0 }, pin: { status: 'new' }, findings: [{ severity: 'medium', rule: 'r', file: 'x.sh', line: 2, message: 'm' }] }),
];
module.exports = { mcpAudits, summary, skills };
