'use strict';
// The standalone verifier (verifier/bb-verify.js) against every spec vector,
// and against a ledger written by the real recorder.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { verifyLedger, fsStore, canon, parseStrict } = require('../verifier/bb-verify');

const DIR = path.join(__dirname, '..', 'docs', 'spec', 'vectors');
const BIN = path.join(__dirname, '..', 'verifier', 'bb-verify.js');
const manifest = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
const read = (f) => fs.readFileSync(path.join(DIR, f), 'utf8');
const set = (xs) => xs.map((x) => `${x.line}:${x.code}`).sort();

test('verifier: canonical forms match the vectors', () => {
  for (const c of JSON.parse(read('canonical.json'))) assert.equal(canon(parseStrict(c.json).value), c.canonical, c.name);
});

for (const c of manifest.cases) {
  test(`verifier: ${c.name}`, () => {
    const opts = {};
    if (c.trusted_key) opts.trustedKey = read(c.trusted_key);
    if (c.anchor) opts.anchors = read(c.anchor).split('\n').filter(Boolean).map((l) => JSON.parse(l));
    if (c.blobs) opts.store = fsStore({ blobs: path.join(DIR, c.blobs), keys: path.join(DIR, c.keys) });
    const r = verifyLedger(read(c.ledger), opts);
    const e = c.expect;
    assert.equal(r.ok, e.ok, JSON.stringify(r.errors));
    assert.deepEqual(set(r.errors), set(e.errors));
    assert.deepEqual(set(r.warnings), set(e.warnings || []));
    assert.equal(r.records, e.records);
    if (e.head) assert.deepEqual(r.head, e.head);
    if (e.erased_keys) assert.deepEqual(r.erased_keys, e.erased_keys);
  });
}

test('verifier: strict JSON parser flags duplicates and rejects junk', () => {
  assert.equal(parseStrict('{"a":1,"a":2}').duplicate, true);
  assert.equal(parseStrict('{"a":{"a":1},"b":[{"a":1}]}').duplicate, false);
  for (const bad of ['{"a":1,}', '{"a":01}', "{'a':1}", '{"a":1} x', '{"a":"\u0001"}', '[1 2]', '']) assert.throws(() => parseStrict(bad), bad);
});

test('verifier: command line exit codes and output', () => {
  const run = (...a) => spawnSync(process.execPath, [BIN, ...a], { encoding: 'utf8' });
  const good = run(path.join(DIR, 'cases/valid-all-kinds/ledger.jsonl'), '--key', path.join(DIR, 'key.pub.pem'));
  assert.equal(good.status, 0);
  assert.match(good.stdout, /^PASS {2}10 records/m);
  const bad = run(path.join(DIR, 'cases/invalid-removed-record/ledger.jsonl'), '--json');
  assert.equal(bad.status, 1);
  assert.deepEqual(set(JSON.parse(bad.stdout).errors), ['4:PREV_MISMATCH', '4:SEQ_GAP']);
  assert.equal(run().status, 2);
  assert.equal(run('/nonexistent.jsonl').status, 2);
  const lvl2 = run(path.join(DIR, 'cases/valid-blobs-erased-session/ledger.jsonl'), '--blobs', path.join(DIR, 'cases/valid-blobs-erased-session/blobs'), '--keys', path.join(DIR, 'cases/valid-blobs-erased-session/keys'));
  assert.equal(lvl2.status, 0, lvl2.stdout);
  assert.match(lvl2.stdout, /1 erased key/);
});

test('verifier: a ledger written by the real recorder passes, edits and crypto-erase included', () => {
  const { Ledger } = require('../dist/src/ledger');
  const { Vault, scopeOf } = require('../dist/src/vault');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-spec-'));
  const P = { home, ledger: path.join(home, 'ledger.jsonl'), blobs: path.join(home, 'blobs'), keys: path.join(home, 'keys') };
  P.privKey = path.join(P.keys, 'ed25519.key'); P.pubKey = path.join(P.keys, 'ed25519.pub');
  for (const d of [P.blobs, P.keys]) fs.mkdirSync(d, { recursive: true });
  const vault = new Vault({ keysDir: P.keys });
  const L = new Ledger(P, { vault });
  const mk = (sid, text) => {
    const b = L.putBlob({ sid, text, note: 'café € 😀' }, scopeOf(sid));
    const summary = 'bbx1:' + vault.seal(scopeOf(sid), Buffer.from(text)).data.toString('base64');
    L.append('hook', { event: 'PreToolUse', session_id: sid, summary, payload: b.sha, payload_size: b.size, key: b.key });
  };
  mk('A', 'keep me'); mk('B', 'erase me'); mk('A', 'and me too');
  const opts = () => ({ trustedKey: fs.readFileSync(P.pubKey, 'utf8'), store: fsStore({ blobs: P.blobs, keys: P.keys }) });
  let r = verifyLedger(fs.readFileSync(P.ledger, 'utf8'), opts());
  assert.ok(r.ok, JSON.stringify(r.errors));
  assert.equal(r.records, 4);
  // erase session B as `blackbox purge` does: destroy the key, write a purge record
  const kidB = vault.kid(scopeOf('B'));
  vault.erase(kidB);
  fs.rmSync(path.join(P.blobs, kidB), { recursive: true, force: true });
  L.append('purge', { erased_keys: [kidB], erased_blobs: 0, erased_raw_bodies: 0, purged_session: 'B' });
  r = verifyLedger(fs.readFileSync(P.ledger, 'utf8'), opts());
  assert.ok(r.ok, JSON.stringify(r.errors));
  assert.deepEqual(r.erased_keys, [kidB]);
  // an edit is caught
  const edited = fs.readFileSync(P.ledger, 'utf8').replace('"PreToolUse"', '"PostToolUse"');
  r = verifyLedger(edited, opts());
  assert.ok(!r.ok);
  assert.ok(r.errors.every((e) => e.code === 'HASH_MISMATCH'));
});
