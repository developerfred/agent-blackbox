'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { merkleRoot, merkleProof, verifyProof } = require('../dist/src/merkle');

const hashes = (n) => Array.from({ length: n }, (_, i) => crypto.createHash('sha256').update('r' + i).digest('hex'));

test('merkle: every record of every batch size has a valid inclusion proof', () => {
  for (let n = 1; n <= 40; n++) {
    const hs = hashes(n);
    const root = merkleRoot(hs);
    for (let i = 0; i < n; i++) {
      const proof = merkleProof(hs, i);
      assert.ok(verifyProof({ hash: hs[i], index: i, size: n, proof, root }), `n=${n} i=${i}`);
    }
  }
});

test('merkle: a changed, moved or foreign record does not verify, and the root changes', () => {
  const hs = hashes(7);
  const root = merkleRoot(hs);
  const proof = merkleProof(hs, 3);
  assert.ok(!verifyProof({ hash: hs[4], index: 3, size: 7, proof, root }));
  assert.ok(!verifyProof({ hash: hs[3], index: 2, size: 7, proof, root }));
  assert.notEqual(merkleRoot([...hs.slice(0, 6), hs[5]]), root);
  assert.notEqual(merkleRoot(hs.slice(0, 6)), root);
});

test('merkle: matches the RFC 6962 definition for a known small tree', () => {
  const [a, b] = hashes(2);
  const leaf = (h) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(h, 'hex')])).digest();
  const want = crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), leaf(a), leaf(b)])).digest('hex');
  assert.equal(merkleRoot([a, b]), want);
});

const fs = require('fs');
const os = require('os');
const path = require('path');
const { Ledger, verify } = require('../dist/src/ledger');

function ledgerWith(n) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-anchor-'));
  const P = { home, ledger: path.join(home, 'ledger.jsonl'), blobs: path.join(home, 'blobs'), keys: path.join(home, 'keys'), privKey: path.join(home, 'p.pem'), pubKey: path.join(home, 'pub.pem') };
  fs.mkdirSync(P.blobs); fs.mkdirSync(P.keys);
  const l = new Ledger(P);
  for (let i = 0; i < n; i++) l.append('hook', { event: 'PreToolUse', session_id: 's', tool_name: 'Bash' });
  return { P, l };
}
const check = (P) => verify({ ledgerPath: P.ledger, pubPem: fs.readFileSync(P.pubKey, 'utf8'), blobsDir: P.blobs });

test('anchor record: verify accepts a correct batch root and rejects a wrong one', () => {
  const { P, l } = ledgerWith(5);
  const hs = fs.readFileSync(P.ledger, 'utf8').trim().split('\n').map((x) => JSON.parse(x).hash);
  l.append('anchor', { alg: 'merkle-sha256-rfc6962', from: 1, to: 6, count: 6, root: merkleRoot(hs) });
  assert.ok(check(P).ok, JSON.stringify(check(P).errors));
  l.append('anchor', { alg: 'merkle-sha256-rfc6962', from: 7, to: 7, count: 1, root: '00'.repeat(32) });
  const r = check(P);
  assert.ok(!r.ok);
  assert.match(r.errors[0].problem, /anchor root does not match/);
});

test('anchor record: an unknown algorithm or a range reaching past itself is an error', () => {
  const { P, l } = ledgerWith(2);
  l.append('anchor', { alg: 'other', from: 1, to: 3, count: 3, root: 'x' });
  assert.match(check(P).errors[0].problem, /malformed/);
  const b = ledgerWith(2);
  b.l.append('anchor', { alg: 'merkle-sha256-rfc6962', from: 1, to: 4, count: 4, root: 'x' });
  assert.match(check(b.P).errors[0].problem, /malformed/);
});
