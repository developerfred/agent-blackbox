'use strict';
// The vectors in docs/spec/vectors are built without src/. These tests check
// that the reference implementation (`blackbox verify`) reports exactly the
// errors the spec requires (section 11 of docs/spec/ledger-v1.md).
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
const set = (xs) => xs.map((x) => `${x.line}:${x.code}`).sort();

for (const c of level1) {
  test(`spec vectors: reference verify agrees on ${c.name}`, () => {
    const r = verify({
      ledgerPath: path.join(DIR, c.ledger),
      pubPem: c.trusted_key ? read(c.trusted_key) : null,
      blobsDir: path.join(DIR, 'no-blobs'),
    });
    assert.equal(r.ok, c.expect.ok, JSON.stringify(r.errors));
    assert.deepEqual(set(r.errors), set(c.expect.errors));
    if (c.expect.ok) {
      assert.equal(r.records, c.expect.records);
      assert.deepEqual(r.head, c.expect.head);
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
