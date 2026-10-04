'use strict';
// Behavior the performance work must not change.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-perf-'));
process.env.BLACKBOX_HOME = path.join(HOME, 'bb');
process.env.BLACKBOX_PORT = String(30000 + Math.floor(Math.random() * 20000));

const { Policy } = require('../dist/src/policy');
const { DEFAULT_CONFIG, ensureDirs, readToken, readAdminToken, P } = require('../dist/src/paths');
const { Daemon } = require('../dist/src/daemon');
const { request } = require('../dist/src/local-http');
const { readJsonl, readJson, parseLine, defined, pushCapped, baseName, isDir, isFile, exists, stablePath } = require('../dist/src/util');

test('util: tolerant JSONL, JSON fallbacks, capped lists, base names', () => {
  const f = path.join(HOME, 'x.jsonl');
  fs.writeFileSync(f, '{"a":1}\n\nnot json\n{"a":2}\n');
  assert.deepEqual(readJsonl(f), [{ a: 1 }, { a: 2 }]);
  assert.deepEqual(readJsonl(path.join(HOME, 'missing')), []);
  assert.equal(readJson(path.join(HOME, 'missing'), 7), 7);
  assert.equal(parseLine('{'), null);
  assert.deepEqual(defined({ a: 1, b: undefined, c: null, d: 0 }), { a: 1, d: 0 });
  assert.deepEqual(pushCapped(['a', 'b'], 'b'), ['a', 'b'], 'no duplicates');
  assert.deepEqual(pushCapped(['a', 'b'], 'c', 2), ['b', 'c'], 'oldest dropped');
  assert.equal(baseName('~/proj/x.sh'), 'x.sh');
  assert.equal(baseName('/', 'fallback'), 'fallback');
  // path kind helpers shared by skills and mcp
  const f2 = path.join(HOME, 'kind.txt');
  fs.writeFileSync(f2, 'x');
  assert.ok(isFile(f2) && !isDir(f2) && exists(f2));
  assert.ok(isDir(HOME) && !isFile(HOME) && exists(HOME));
  assert.ok(!isFile(path.join(HOME, 'nope')) && !isDir(path.join(HOME, 'nope')) && !exists(path.join(HOME, 'nope')));
});

test('local-http: content-length and chunked responses, errors, timeouts', async () => {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (req.url === '/echo') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ got: Buffer.concat(chunks).toString(), token: req.headers['x-blackbox-token'], method: req.method })); }
      if (req.url === '/chunked') { res.writeHead(200); res.write('{"a":'); res.write('[1,2,3]'); return res.end('}'); }
      if (req.url === '/slow') return; // never answers
      res.writeHead(500); res.end('boom');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = /** @type {any} */ (server.address()).port;
  try {
    assert.deepEqual((await request({ port, method: 'POST', path: '/echo', token: 'tk', body: { x: 'é' } })).body, { got: '{"x":"é"}', token: 'tk', method: 'POST' });
    assert.deepEqual((await request({ port, path: '/chunked' })).body, { a: [1, 2, 3] });
    const bad = await request({ port, path: '/nope' });
    assert.equal(bad.status, 500);
    assert.equal(bad.body, null, 'a non-JSON body is null, not an error');
    await assert.rejects(request({ port, path: '/slow', timeout: 100 }), /timeout/);
  } finally { server.closeAllConnections(); server.close(); }
  await assert.rejects(request({ port: 1, path: '/' }));
});

test('policy: the length filter finds exactly the secrets an unfiltered scan finds', () => {
  const mk = () => new Policy(DEFAULT_CONFIG, { sessions: {} }, 'salt');
  const secrets = ['abcd1234efgh5678', 'zzzz9999yyyy8888wwww7777', 'Qw3rtyUiop'];
  const texts = [
    `k=${secrets[0]} and ${secrets[1]}`, `nothing here at all, just words of assorted lengths`, `${secrets[2]}:${secrets[0]}`,
    `x=${'a'.repeat(16)} y=${'b'.repeat(24)} z=${'c'.repeat(10)}`, secrets.join(' '),
  ];
  const filtered = mk();
  filtered.postToolUse({ session_id: 's', tool_name: 'Read', tool_input: { file_path: '/r/.env' }, tool_response: { file: { content: secrets.map((s, i) => `TOKEN_${i}=${s}`).join('\n') } } });
  // a session saved by an older version has no length list: nothing is skipped
  const legacy = mk();
  legacy.state.sessions.s = JSON.parse(JSON.stringify(filtered.state.sessions.s));
  delete legacy.state.sessions.s.secretLens;
  assert.ok(filtered.state.sessions.s.secretLens.length >= 2);
  for (const t of texts) {
    assert.equal(filtered.scrubText(t, filtered.state.sessions.s), legacy.scrubText(t, legacy.state.sessions.s), t);
    assert.equal(filtered.containsKnownSecret(filtered.state.sessions.s, t), legacy.containsKnownSecret(legacy.state.sessions.s, t), t);
  }
  assert.ok(!filtered.scrubText(texts[0], filtered.state.sessions.s).includes(secrets[0]));
  // a secret learned later still counts
  filtered.postToolUse({ session_id: 's', tool_name: 'Read', tool_input: { file_path: '/r/.env' }, tool_response: { file: { content: 'LATE_KEY=late-value-of-odd-length-123' } } });
  assert.ok(!filtered.scrubText('x late-value-of-odd-length-123 y', filtered.state.sessions.s).includes('late-value'));
});

test('daemon: payload lookup by record number, across restarts; state is flushed on stop', async () => {
  ensureDirs();
  const port = Number(process.env.BLACKBOX_PORT);
  const tok = { 'x-blackbox-token': readToken() };
  const adm = { 'x-blackbox-token': readAdminToken() };
  const call = (method, p, body, headers) => request({ port, method, path: p, token: headers['x-blackbox-token'], body });
  let d = new Daemon();
  let server = await d.listen(port);
  d.start();
  let seqOfSecond;
  try {
    for (let i = 0; i < 30; i++) {
      await call('POST', '/hook', { hook_event_name: 'PostToolUse', session_id: `p${i % 3}`, tool_name: 'Bash', tool_input: { command: `echo ${i}` }, tool_response: `out-${i}` }, tok);
    }
    const events = (await call('GET', '/api/events?session=p1', null, adm)).body;
    const rec = events.find((r) => r.summary && r.summary.includes('echo 4'));
    assert.ok(rec, 'found the record');
    seqOfSecond = rec.seq;
    const got = await call('GET', `/api/payload?seq=${rec.seq}`, null, adm);
    assert.equal(got.status, 200);
    assert.equal(got.body.payload.tool_input.command, 'echo 4');
    assert.equal((await call('GET', '/api/payload?seq=99999', null, adm)).status, 404);
    d.flushState();
    assert.ok(fs.existsSync(P.state));
  } finally { server.closeAllConnections(); server.close(); }
  // a restarted daemon rebuilds the offsets from the file
  d = new Daemon();
  server = await d.listen(port);
  d.start();
  try {
    const got = await call('GET', `/api/payload?seq=${seqOfSecond}`, null, adm);
    assert.equal(got.body.payload.tool_input.command, 'echo 4');
    // records appended after a restart are found too
    await call('POST', '/hook', { hook_event_name: 'PostToolUse', session_id: 'late', tool_name: 'Bash', tool_input: { command: 'echo late' }, tool_response: 'x' }, tok);
    const late = (await call('GET', '/api/events?session=late', null, adm)).body[0];
    assert.equal((await call('GET', `/api/payload?seq=${late.seq}`, null, adm)).body.payload.tool_input.command, 'echo late');
  } finally { server.closeAllConnections(); server.close(); }
});

test('cli token: a leftover admin-token is not sent when the recorder runs as its own user', () => {
  const { cliToken } = require('../dist/src/paths');
  ensureDirs();
  fs.writeFileSync(P.token, 'ingest-token');
  fs.writeFileSync(P.adminToken, 'stale-admin-token');
  const original = fs.existsSync(P.config) ? fs.readFileSync(P.config, 'utf8') : null;
  try {
    // recorder as the same user: unchanged, the admin token wins
    fs.writeFileSync(P.config, JSON.stringify({}));
    assert.equal(cliToken(false), 'stale-admin-token');
    assert.equal(cliToken(true), 'stale-admin-token');
    // recorder as its own user: the stale file belongs to a recorder that is gone and would be refused
    fs.writeFileSync(P.config, JSON.stringify({ remoteDaemon: true }));
    assert.equal(cliToken(false), 'ingest-token');
    assert.equal(cliToken(true), 'ingest-token', 'without sudo access it falls back to the ingest token (a 403, not a wrong 401)');
    // and the folder stops growing an admin token of its own
    fs.rmSync(P.adminToken);
    ensureDirs();
    assert.ok(!fs.existsSync(P.adminToken));
    fs.writeFileSync(P.config, JSON.stringify({}));
    ensureDirs();
    assert.ok(fs.existsSync(P.adminToken), 'same-user mode still creates it');
  } finally {
    if (original == null) fs.rmSync(P.config, { force: true }); else fs.writeFileSync(P.config, original);
  }
});

test('util: stablePath maps a Homebrew Cellar path to its opt symlink, only when that exists', () => {
  const prefix = path.join(HOME, 'brew');
  const cellar = path.join(prefix, 'Cellar', 'node', '26.7.0', 'bin', 'node');
  fs.mkdirSync(path.dirname(cellar), { recursive: true });
  fs.writeFileSync(cellar, '');
  assert.equal(stablePath(cellar), cellar, 'no opt link yet: unchanged');
  fs.mkdirSync(path.join(prefix, 'opt', 'node', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(prefix, 'opt', 'node', 'bin', 'node'), '');
  assert.equal(stablePath(cellar), path.join(prefix, 'opt', 'node', 'bin', 'node'));
  assert.equal(stablePath('/usr/local/bin/node'), '/usr/local/bin/node');
});
