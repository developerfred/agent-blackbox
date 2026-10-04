'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.BLACKBOX_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-mcp-home-'));
process.env.BLACKBOX_PORT = String(19900 + Math.floor(Math.random() * 90));
delete process.env.CLAUDE_CONFIG_DIR;

const { auditServers, saveMcpPins, parseToolName, codexServers } = require('../dist/src/mcp');

const write = (f, t) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, typeof t === 'string' ? t : JSON.stringify(t, null, 2)); };
// built at runtime so no token-shaped literal sits in the repository
const fakeToken = 'gh' + 'p_' + 'zyxwvutsrqponmlkjihgfedcba9876543210';

function fixture() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-mcph-'));
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-mcpc-'));
  write(path.join(home, '.claude.json'), {
    mcpServers: {
      github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: fakeToken } },
      pinned: { command: 'npx', args: ['-y', '@acme/mcp@1.4.2'], env: { API_KEY: '${ACME_KEY}' } },
    },
    projects: { [cwd]: { mcpServers: { files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2.0.0', home] } } } },
  });
  write(path.join(cwd, '.mcp.json'), { mcpServers: { local: { command: './bin/server', args: [] }, wrapped: { command: 'bash', args: ['-c', 'node srv.js'] } } });
  write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { remote: { url: 'http://mcp.example.net/sse' }, safe: { url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${TOKEN}' } } } });
  write(path.join(home, '.codex', 'config.toml'), '[mcp_servers.box]\ncommand = "docker"\nargs = ["run", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "acme/box:1.0"]\n\n[mcp_servers.box.env]\nLOG = "1"\n');
  write(path.join(home, '.claude', 'plugins', 'cache', 'mkt', 'db-plugin', '.mcp.json'), { mcpServers: { db: { command: 'node', args: ['${CLAUDE_PLUGIN_ROOT}/server.js'] } } });
  return { home, cwd };
}

test('mcp: finds servers in every client config, including plugins and Codex TOML', () => {
  const { home, cwd } = fixture();
  const A = auditServers({ home, cwd });
  const key = (a) => `${a.client}/${a.scope}/${a.name}`;
  assert.deepEqual(A.map(key).sort(), [
    'Claude Code/local/files', 'Claude Code/plugin/db', 'Claude Code/project/local', 'Claude Code/project/wrapped',
    'Claude Code/user/github', 'Claude Code/user/pinned', 'Codex/user/box', 'Cursor/user/remote', 'Cursor/user/safe',
  ]);
  assert.deepEqual(codexServers(path.join(home, '.codex', 'config.toml')).box.env, { LOG: '1' });
});

test('mcp: config audit flags the risky definitions and leaves safe ones alone', () => {
  const { home, cwd } = fixture();
  const A = auditServers({ home, cwd });
  const rules = (n) => A.find((a) => a.name === n).findings.map((f) => f.rule);
  assert.ok(rules('github').includes('plaintext-secret'));
  assert.ok(rules('github').includes('unpinned-package'));
  assert.ok(rules('files').includes('broad-filesystem'));
  assert.ok(rules('local').includes('repo-executable'));
  assert.ok(rules('wrapped').includes('shell-wrapper'));
  assert.ok(rules('remote').includes('insecure-transport'));
  assert.ok(rules('box').includes('docker-privileged') && rules('box').includes('docker-socket'));
  assert.deepEqual(rules('pinned'), [], 'pinned version + ${VAR} reference is clean');
  assert.deepEqual(rules('safe'), [], 'https + ${VAR} header is clean');
  assert.ok(!JSON.stringify(A).includes(fakeToken), 'the token value is never kept or printed');
});

test('mcp: a pinned definition that changes is flagged', () => {
  const { home, cwd } = fixture();
  const pins = path.join(process.env.BLACKBOX_HOME, 'mcp-pins.json');
  saveMcpPins(pins, auditServers({ home, cwd }));
  assert.ok(auditServers({ home, cwd, pinsFile: pins }).every((a) => a.pin === 'pinned'));
  const cfg = JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf8'));
  cfg.mcpServers.pinned.args = ['-y', '@acme/mcp@1.4.3'];
  write(path.join(home, '.claude.json'), cfg);
  const changed = auditServers({ home, cwd, pinsFile: pins }).find((a) => a.name === 'pinned');
  assert.equal(changed.pin, 'changed');
  assert.equal(changed.risk, 'high');
});

test('mcp: tool names parse into server, tool and plugin; verbs mark outbound', () => {
  assert.deepEqual(parseToolName('mcp__github__create_issue'), { server: 'github', tool: 'create_issue', plugin: null, outbound: true });
  assert.deepEqual(parseToolName('mcp__plugin_db-plugin_db__query'), { server: 'db', tool: 'query', plugin: 'db-plugin', outbound: false });
  assert.equal(parseToolName('mcp__remote-devices__device_commit_files').outbound, true);
  assert.equal(parseToolName('Bash'), null);
});

test('mcp: scan reports usage per server and joins the config audit', () => {
  const { home, cwd } = fixture();
  const { scan } = require('../dist/src/scan');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-mcpscan-'));
  const L = [
    { type: 'assistant', sessionId: 'm1', cwd: '/w', timestamp: '2026-10-01T10:00:00Z', message: { content: [
      { type: 'tool_use', id: 'a', name: 'mcp__github__search_issues', input: { q: 'x' } },
      { type: 'tool_use', id: 'b', name: 'mcp__github__create_issue', input: { title: 'y' } },
      { type: 'tool_use', id: 'c', name: 'mcp__github__create_issue', input: { title: 'z' } }] } },
    { type: 'user', sessionId: 'm1', cwd: '/w', timestamp: '2026-10-01T10:00:01Z', message: { content: [
      { type: 'tool_result', tool_use_id: 'a', content: 'ok' }, { type: 'tool_result', tool_use_id: 'b', content: 'ok' }, { type: 'tool_result', tool_use_id: 'c', content: 'denied', is_error: true }] } },
  ];
  write(path.join(dir, 'p', 'm1.jsonl'), L.map((l) => JSON.stringify(l)).join('\n'));
  const S = scan({ projectsDir: dir, days: 3650, mcpAudits: auditServers({ home, cwd }) });
  const gh = S.mcp.used.find((m) => m.server === 'github');
  assert.deepEqual([gh.calls, gh.outboundCalls, gh.errors], [3, 2, 1]);
  assert.equal(gh.configured[0].risk, 'high');
  assert.ok(S.mcp.unused.some((u) => u.server === 'box'), 'configured but unused servers are listed');
  const { renderHtml } = require('../dist/src/scan-html');
  assert.ok(renderHtml(S).includes('MCP servers'));
});

test('mcp: the daemon asks before calling a tool of a high-risk server', () => {
  const { home, cwd } = fixture();
  const { ensureDirs } = require('../dist/src/paths');
  ensureDirs();
  const { Daemon } = require('../dist/src/daemon');
  const d = new Daemon();
  d.start();
  d.mcpAudits = auditServers({ home, cwd });
  const out = d.handleHook({ hook_event_name: 'PreToolUse', session_id: 'g', tool_name: 'mcp__github__create_issue', tool_input: { title: 'a' }, tool_use_id: 't' });
  assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /plaintext-secret/);
  assert.equal(d.handleHook({ hook_event_name: 'PreToolUse', session_id: 'g', tool_name: 'mcp__pinned__list', tool_input: {}, tool_use_id: 'u' }), null);
});
