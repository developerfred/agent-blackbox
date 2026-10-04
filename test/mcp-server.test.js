'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFile } = require('child_process');
const { promisify } = require('util');
const run = promisify(execFile);

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-mcps-'));
process.env.BLACKBOX_HOME = HOME;
process.env.BLACKBOX_PORT = String(22000 + Math.floor(Math.random() * 900));

const { ensureDirs, readToken } = require('../dist/src/paths');
const { Daemon } = require('../dist/src/daemon');
const { listTools } = require('../dist/src/mcp-server');
const BIN = path.join(__dirname, '..', 'dist', 'bin', 'blackbox.js');

function rpc(args, messages) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, 'serve-mcp', ...args], { env: process.env });
    let out = '';
    child.stdout.on('data', (d) => { out += d; if (out.trim().split('\n').length >= messages.filter((m) => m.id !== undefined).length) child.kill(); });
    child.on('close', () => resolve(out.trim().split('\n').filter(Boolean).map(JSON.parse)));
    for (const m of messages) child.stdin.write(JSON.stringify(m) + '\n');
  });
}

test('mcp server: public tools by default, admin tools only with --admin, read-only annotations', async () => {
  assert.deepEqual(listTools().map((t) => t.name), ['blackbox_capabilities', 'blackbox_status', 'blackbox_rules']);
  assert.ok(listTools({ admin: true }).some((t) => t.name === 'blackbox_records'));
  assert.ok(listTools({ admin: true }).every((t) => t.annotations.readOnlyHint === true));
});

test('mcp server: stdio round trip against a live recorder, and the --json CLI modes', async () => {
  ensureDirs();
  const d = new Daemon();
  const port = Number(process.env.BLACKBOX_PORT);
  const server = await d.listen(port);
  d.start();
  try {
    const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } };
    const res = await rpc([], [init, { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'blackbox_status', arguments: {} } },
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'blackbox_records', arguments: {} } },
      { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'blackbox_capabilities' } }]);
    const by = Object.fromEntries(res.map((r) => [r.id, r]));
    assert.equal(by[1].result.serverInfo.name, 'agent-blackbox');
    assert.equal(by[1].result.protocolVersion, '2025-06-18');
    assert.deepEqual(by[2].result.tools.map((t) => t.name), ['blackbox_capabilities', 'blackbox_status', 'blackbox_rules']);
    assert.equal(by[3].result.structuredContent.chain_ok, true);
    assert.equal(by[4].error.code, -32602, 'records is not offered without --admin');
    assert.equal(by[5].result.structuredContent.schema, 'blackbox.agent/v1');

    const adm = await rpc(['--admin'], [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'blackbox_records', arguments: { kind: 'decision', limit: 5 } } }]);
    assert.equal(adm[0].result.structuredContent.schema, 'blackbox.agent/v1');

    // CLI --json modes print one parseable document
    // async: the recorder runs in this process, so a blocking exec would starve it
    const cli = async (...a) => JSON.parse((await run(process.execPath, [BIN, ...a, '--json'], { env: process.env })).stdout);
    assert.equal((await cli('status')).recording, true);
    assert.deepEqual((await cli('sessions')).sessions, []);
    assert.equal((await cli('verify')).ok, true);
    assert.equal((await cli('timeline')).session, null);
    assert.deepEqual((await cli('docs')).docs, []);
  } finally {
    d.flushState();
    server.close();
    for (const t of [d.bodyTimer, d.skillTimer, d.integrityTimer, d.retentionTimer]) clearInterval(t);
  }
});
