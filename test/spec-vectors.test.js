'use strict';
// The vectors in docs/spec/vectors are built without src/. These tests check
// that the reference implementation agrees with them where it implements the
// rule (section 11 of docs/spec/ledger-v1.md); the gaps it has are listed in
// the spec under "Reference implementation notes".
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { canon, sha256, verify } = require('../dist/src/ledger');

const DIR = path.join(__dirname, '..', 'docs', 'spec', 'vectors');
const manifest = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
const read = (f) => fs.readFileSync(path.join(DIR, f), 'utf8');

test('spec vectors: canonical forms match src/ledger.js canon()', () => {
  for (const c of JSON.parse(read('canonical.json'))) {
    assert.equal(canon(JSON.parse(c.json)), c.canonical, c.name);
    assert.equal(sha256(c.canonical), c.sha256, c.name);
  }
});

const level1 = manifest.cases.filter((c) => c.level === 1 && !c.anchor);
// Reference verify() takes any key from genesis unless one is given; the
// vectors that need rules it lacks (see the spec's implementation notes) are skipped.
const refGaps = new Set(['invalid-second-genesis', 'invalid-no-genesis', 'invalid-key-id-mismatch', 'invalid-unsupported-version', 'invalid-duplicate-key', 'invalid-empty-ledger']);

for (const c of level1) {
  if (refGaps.has(c.name)) continue;
  test(`spec vectors: reference verify agrees on ${c.name}`, () => {
    const r = verify({
      ledgerPath: path.join(DIR, c.ledger),
      pubPem: c.trusted_key ? read(c.trusted_key) : null,
      blobsDir: path.join(DIR, 'no-blobs'),
    });
    assert.equal(r.ok, c.expect.ok, JSON.stringify(r.errors));
    if (c.expect.ok) {
      assert.equal(r.records, c.expect.records);
      assert.deepEqual(r.head, c.expect.head);
    } else {
      // same lines flagged (the reference reports messages, not codes)
      const lines = (xs) => [...new Set(xs.map((e) => e.line))].sort((a, b) => a - b);
      assert.deepEqual(lines(r.errors), lines(c.expect.errors));
    }
  });
}

test('spec vectors: the reference chain head matches an anchor taken from the same ledger', () => {
  const c = manifest.cases.find((x) => x.name === 'valid-anchor');
  const a = JSON.parse(read(c.anchor));
  const r = verify({ ledgerPath: path.join(DIR, c.ledger), blobsDir: path.join(DIR, 'no-blobs') });
  assert.ok(r.ok);
  const recs = read(c.ledger).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(recs[a.seq - 1].hash, a.hash);
});
