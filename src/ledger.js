'use strict';
// Append-only, hash-chained, Ed25519-signed evidence ledger.
// Each line is one record. hash = sha256(canonical(record without hash/sig)),
// sig = Ed25519(hash). Payloads live in a content-addressed blob store; the
// record only carries their sha256, so content can be crypto-erased later
// without breaking the chain.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const GENESIS = '0'.repeat(64);

function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort()
    .map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function loadOrCreateKeys(P) {
  if (!fs.existsSync(P.privKey)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(P.privKey, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(P.pubKey, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  }
  const priv = crypto.createPrivateKey(fs.readFileSync(P.privKey));
  const pubPem = fs.readFileSync(P.pubKey, 'utf8');
  const pub = crypto.createPublicKey(pubPem);
  const keyId = sha256(pub.export({ type: 'spki', format: 'der' })).slice(0, 16);
  return { priv, pub, pubPem, keyId };
}

function readLastLine(file) {
  if (!fs.existsSync(file)) return null;
  const size = fs.statSync(file).size;
  if (!size) return null;
  const len = Math.min(size, 1 << 20);
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(len);
  fs.readSync(fd, buf, 0, len, size - len);
  fs.closeSync(fd);
  const lines = buf.toString('utf8').split('\n').filter(Boolean);
  return lines.length ? lines[lines.length - 1] : null;
}

class Ledger {
  constructor(P) {
    this.P = P;
    this.keys = loadOrCreateKeys(P);
    const last = readLastLine(P.ledger);
    if (last) {
      const rec = JSON.parse(last);
      this.seq = rec.seq;
      this.head = rec.hash;
    } else {
      this.seq = 0;
      this.head = GENESIS;
      this.append('genesis', { key_id: this.keys.keyId, public_key: this.keys.pubPem });
    }
  }

  // Store content by its hash; returns the digest recorded in the chain.
  putBlob(content) {
    const buf = Buffer.isBuffer(content) ? content
      : Buffer.from(typeof content === 'string' ? content : canon(content));
    const digest = sha256(buf);
    const file = path.join(this.P.blobs, digest);
    if (!fs.existsSync(file)) fs.writeFileSync(file, buf, { mode: 0o600 });
    return { sha: digest, size: buf.length };
  }

  // Move a file into the blob store (used for raw API bodies).
  adoptFile(src) {
    const buf = fs.readFileSync(src);
    const digest = sha256(buf);
    const file = path.join(this.P.blobs, digest);
    if (fs.existsSync(file)) fs.unlinkSync(src); else fs.renameSync(src, file);
    try { fs.chmodSync(file, 0o600); } catch { /* best effort */ }
    return { sha: digest, size: buf.length };
  }

  append(kind, fields) {
    const rec = { v: 1, seq: this.seq + 1, ts: new Date().toISOString(), kind, ...fields, prev: this.head };
    const hash = sha256(canon(rec));
    const sig = crypto.sign(null, Buffer.from(hash, 'hex'), this.keys.priv).toString('base64');
    const full = { ...rec, hash, sig };
    fs.appendFileSync(this.P.ledger, JSON.stringify(full) + '\n', { mode: 0o600 });
    this.seq = rec.seq;
    this.head = hash;
    return full;
  }
}

const BLOB_FIELDS = ['payload', 'request_blob', 'response_blob'];

// Walk the whole chain. Integrity proves nothing recorded was changed,
// removed or reordered; it does not prove that everything was recorded.
function verify({ ledgerPath, pubPem, blobsDir }) {
  const out = { ok: true, records: 0, errors: [], warnings: [], head: null, sessions: new Set() };
  if (!fs.existsSync(ledgerPath)) {
    out.ok = false; out.errors.push({ line: 0, problem: 'ledger not found' }); return out;
  }
  const pub = pubPem ? crypto.createPublicKey(pubPem) : null;
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n');
  let prev = GENESIS;
  let expectSeq = 1;
  let chainPub = pub;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const fail = (problem) => { out.ok = false; out.errors.push({ line: i + 1, problem }); };
    let rec;
    try { rec = JSON.parse(line); } catch { fail('not valid JSON'); continue; }
    out.records++;
    const { hash, sig, ...body } = rec;
    if (rec.seq !== expectSeq) fail(`sequence gap: expected ${expectSeq}, found ${rec.seq}`);
    if (rec.prev !== prev) fail(`seq ${rec.seq}: prev does not match the previous record's hash (record removed, inserted or reordered)`);
    if (sha256(canon(body)) !== hash) fail(`seq ${rec.seq}: content does not match its hash (record edited)`);
    if (rec.kind === 'genesis') {
      const gpub = crypto.createPublicKey(rec.public_key);
      if (pub && pub.export({ type: 'spki', format: 'der' }).compare(gpub.export({ type: 'spki', format: 'der' })) !== 0) {
        fail('genesis key differs from the trusted public key (chain rewritten with another key)');
      }
      chainPub = pub || gpub;
    }
    try {
      if (!chainPub || !crypto.verify(null, Buffer.from(hash, 'hex'), chainPub, Buffer.from(sig, 'base64'))) {
        fail(`seq ${rec.seq}: bad signature`);
      }
    } catch { fail(`seq ${rec.seq}: unreadable signature`); }
    for (const f of BLOB_FIELDS) {
      const d = rec[f];
      if (!d) continue;
      const file = path.join(blobsDir, d);
      if (!fs.existsSync(file)) out.warnings.push(`seq ${rec.seq}: ${f} blob missing (erased or not copied)`);
      else if (sha256(fs.readFileSync(file)) !== d) fail(`seq ${rec.seq}: ${f} blob content changed`);
    }
    if (rec.session_id) out.sessions.add(rec.session_id);
    prev = hash;
    expectSeq = rec.seq + 1;
    out.head = { seq: rec.seq, hash };
  }
  out.sessions = out.sessions.size;
  return out;
}

module.exports = { Ledger, verify, canon, sha256, GENESIS };
