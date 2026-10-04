'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Vault, KeyErased, scopeOf } = require('../dist/src/vault');
const { Ledger, verify } = require('../dist/src/ledger');

function tmpHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-vault-'));
  const P = { home, ledger: path.join(home, 'ledger.jsonl'), blobs: path.join(home, 'blobs'), keys: path.join(home, 'keys') };
  P.privKey = path.join(P.keys, 'ed25519.key'); P.pubKey = path.join(P.keys, 'ed25519.pub');
  for (const d of [P.blobs, P.keys]) fs.mkdirSync(d, { recursive: true });
  return P;
}

test('vault: seal/open round trip, key ids hide the scope, tampering is detected', () => {
  const P = tmpHome();
  const v = new Vault({ keysDir: P.keys });
  const { kid, data } = v.seal('session:xyz-private', Buffer.from('hello secret world'));
  assert.ok(Vault.isSealed(data));
  assert.ok(!data.includes(Buffer.from('hello')));
  // hex never contains 'x', so this cannot fail by chance (a random id can contain "abc")
  assert.ok(!kid.includes('xyz'));
  assert.ok(!data.includes(Buffer.from('xyz')));
  assert.equal(v.open(data).toString(), 'hello secret world');
  // a second vault from the same master key reads it (daemon restart)
  assert.equal(new Vault({ keysDir: P.keys }).open(data).toString(), 'hello secret world');
  const bad = Buffer.from(data); bad[bad.length - 1] ^= 1;
  assert.throws(() => v.open(bad));
  // wrong master key cannot unwrap the session key
  assert.throws(() => new Vault({ keysDir: P.keys, masterKey: 'ab'.repeat(32) }).open(data));
  // session keys on disk are wrapped, never the raw key
  const keyFile = fs.readFileSync(path.join(P.keys, 'sessions', `${kid}.key`), 'utf8');
  assert.ok(Buffer.from(keyFile, 'base64').length === 12 + 16 + 32);
});

test('vault: erasing one session key makes only that session unreadable', () => {
  const P = tmpHome();
  const vault = new Vault({ keysDir: P.keys });
  const L = new Ledger(P, { vault });
  const put = (sid, i) => { const b = L.putBlob({ sid, i }, scopeOf(sid)); return L.append('hook', { session_id: sid, payload: b.sha, key: b.key }); };
  const a = put('A', 1); put('A', 2); const b = put('B', 1);
  const pubPem = fs.readFileSync(P.pubKey, 'utf8');
  let r = verify({ ledgerPath: P.ledger, pubPem, blobsDir: P.blobs, vault });
  assert.ok(r.ok, JSON.stringify(r.errors));
  assert.equal(JSON.parse(L.getBlob(a.payload, a.key)).sid, 'A');

  // copy the blobs aside (a "backup") before erasing
  const backup = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-backup-'));
  fs.cpSync(P.blobs, backup, { recursive: true });
  assert.ok(vault.erase(a.key));
  assert.throws(() => L.getBlob(a.payload, a.key), KeyErased);
  // even the backup copy is useless now
  const fresh = new Vault({ keysDir: P.keys });
  assert.throws(() => fresh.open(fs.readFileSync(path.join(backup, a.key, a.payload))), KeyErased);
  // session B is untouched
  assert.equal(JSON.parse(new Ledger(P, { vault: fresh }).getBlob(b.payload, b.key)).sid, 'B');

  r = verify({ ledgerPath: P.ledger, pubPem, blobsDir: P.blobs, vault: fresh });
  assert.ok(r.ok, JSON.stringify(r.errors));
  assert.equal(r.erasedKeys, 1);

  // swapping an encrypted blob for another one is caught
  const target = path.join(P.blobs, b.key, b.payload);
  const other = L.putBlob({ evil: true }, scopeOf('B'));
  fs.copyFileSync(path.join(P.blobs, other.key, other.sha), target);
  r = verify({ ledgerPath: P.ledger, pubPem, blobsDir: P.blobs, vault: fresh });
  assert.ok(!r.ok);
  assert.match(r.errors[0].problem, /blob content changed/);
});

test('scopeOf: sessions get their own key, records without one share a month key', () => {
  assert.equal(scopeOf('s1'), 'session:s1');
  assert.equal(scopeOf(null, '2026-10-03T10:00:00Z'), 'month:2026-10');
});
