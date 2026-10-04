#!/usr/bin/env node
'use strict';
// Standalone verifier for the agent-blackbox ledger format v1
// (docs/spec/ledger-v1.md). One file, no dependencies, Node 18+. It shares no
// code with the recorder: copy this file anywhere and it still works.
//
//   node bb-verify.js ledger.jsonl [--key pub.pem] [--anchor anchors.jsonl]
//                     [--blobs DIR [--keys DIR] [--master-key HEX]] [--json]
//
// Exit code: 0 the ledger passed, 1 it did not, 2 bad usage.
//
// Level 1 (chain) needs only the ledger. Level 2 (--blobs) also checks the
// payload blobs; sealed ones need --keys (the recorder's keys folder, or a
// copy of it with master.key and sessions/) or --master-key.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const GENESIS = '0'.repeat(64);
const MAGIC = Buffer.from('BBX1');
const BLOB_FIELDS = ['payload', 'request_blob', 'response_blob'];
const sha256 = (d) => crypto.createHash('sha256').update(d).digest('hex');
const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);

// ---- strict JSON: JSON.parse that also reports duplicate keys ----
// Returns { value, duplicate } or throws on invalid JSON.
function parseStrict(text) {
  let i = 0;
  let duplicate = false;
  const ws = () => { while (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r') i++; };
  const fail = () => { throw new SyntaxError('invalid JSON'); };
  function str() {
    const start = i;
    if (text[i] !== '"') fail();
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text.charCodeAt(i) < 0x20) fail();
      if (text[i] === '\\') i++;
      i++;
    }
    if (text[i] !== '"') fail();
    i++;
    return JSON.parse(text.slice(start, i)); // validates escapes, handles surrogates
  }
  function val() {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; ws();
      const o = {};
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws();
        const k = str();
        ws();
        if (text[i++] !== ':') fail();
        if (Object.prototype.hasOwnProperty.call(o, k)) duplicate = true;
        Object.defineProperty(o, k, { value: val(), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return o; }
        fail();
      }
    }
    if (c === '[') {
      i++; ws();
      const a = [];
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(val());
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return a; }
        fail();
      }
    }
    if (c === '"') return str();
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 400));
    if (!m) fail();
    i += m[0].length;
    return JSON.parse(m[0]);
  }
  const value = val();
  ws();
  if (i !== text.length) fail();
  return { value, duplicate };
}

// ---- section 4: canonical form ----
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

const spkiDer = (key) => key.export({ type: 'spki', format: 'der' });

// ---- section 7, 8: sealed envelopes and key unwrapping ----
function openSealed(key, sealed) {
  const kid = sealed.subarray(4, 12);
  const iv = sealed.subarray(12, 24);
  const tag = sealed.subarray(24, 40);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.concat([MAGIC, kid]));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(sealed.subarray(40)), d.final()]);
}
const isSealed = (b) => b.length >= 40 && b.subarray(0, 4).equals(MAGIC);

// store: { blob(key, digest) -> Buffer | null, dataKey(kid) -> Buffer | null }
function fsStore({ blobs, keys, masterKey }) {
  let master = masterKey ? Buffer.from(masterKey, 'hex') : null;
  if (!master && keys && fs.existsSync(path.join(keys, 'master.key'))) {
    master = Buffer.from(fs.readFileSync(path.join(keys, 'master.key'), 'utf8').trim(), 'hex');
  }
  const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f) : null);
  return {
    blob: (key, digest) => read(key ? path.join(blobs, key, digest) : path.join(blobs, digest)),
    haveKeys: !!(master && keys),
    dataKey(kid) {
      const f = keys && path.join(keys, 'sessions', `${kid}.key`);
      if (!master || !f || !fs.existsSync(f)) return null;
      const b = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', master, b.subarray(0, 12));
      d.setAAD(Buffer.from('wrap:' + kid));
      d.setAuthTag(b.subarray(12, 28));
      return Buffer.concat([d.update(b.subarray(28)), d.final()]);
    },
  };
}

/**
 * Verify a ledger.
 * @param {string} text ledger contents (JSON Lines)
 * @param {{ trustedKey?: string, anchors?: any[], store?: ReturnType<typeof fsStore> }} [opts]
 *   trustedKey: SPKI PEM obtained out of band. anchors: objects with seq and hash.
 *   store: enables level 2 (blob checks).
 */
function verifyLedger(text, { trustedKey = null, anchors = [], store = null } = {}) {
  const out = { ok: true, level: store ? 2 : 1, records: 0, head: null, errors: [], warnings: [], erased_keys: [] };
  const err = (line, code, message) => { out.ok = false; out.errors.push({ line, code, message }); };
  const warn = (line, code, message) => out.warnings.push({ line, code, message });

  let trusted = null;
  if (trustedKey) trusted = crypto.createPublicKey(trustedKey);
  let chainKey = trusted;
  const lines = text.split('\n');
  const parsed = [];
  const purged = new Set();
  let prev = GENESIS;
  let expectSeq = 1;
  const bySeq = new Map();

  for (let n = 0; n < lines.length; n++) {
    const line = n + 1;
    if (!lines[n].trim()) continue;
    let rec;
    try {
      const r = parseStrict(lines[n]);
      rec = r.value;
      if (!rec || typeof rec !== 'object' || Array.isArray(rec)) throw new SyntaxError('not an object');
      if (r.duplicate) err(line, 'DUPLICATE_KEY', 'a key appears twice in the record');
    } catch { err(line, 'INVALID_JSON', 'not a JSON object'); continue; }

    const first = out.records === 0;
    out.records++;
    parsed.push([line, rec]);
    bySeq.set(rec.seq, rec.hash);
    if (rec.kind === 'purge' && Array.isArray(rec.erased_keys)) for (const k of rec.erased_keys) purged.add(k);

    const label = `seq ${rec.seq}`;
    const unsupported = rec.v !== 1;
    if (unsupported) err(line, 'UNSUPPORTED_VERSION', `${label}: record version ${JSON.stringify(rec.v)} is not supported`);
    if (rec.seq !== expectSeq) err(line, 'SEQ_GAP', `${label}: expected ${expectSeq}`);
    if (rec.prev !== prev) err(line, 'PREV_MISMATCH', `${label}: prev is not the previous record's hash (removed, inserted or reordered)`);

    // genesis rules; the chain key is the trusted key if one was given, else the genesis key
    if (first && rec.kind !== 'genesis') err(line, 'GENESIS_REQUIRED', `${label}: the first record must be genesis`);
    if (!first && rec.kind === 'genesis') err(line, 'GENESIS_DUPLICATE', `${label}: only the first record may be genesis`);
    if (first && rec.kind === 'genesis') {
      let gk = null;
      try { gk = crypto.createPublicKey(rec.public_key); } catch { /* reported below */ }
      if (!gk || sha256(spkiDer(gk)).slice(0, 16) !== rec.key_id) err(line, 'KEY_ID_MISMATCH', `${label}: key_id does not match public_key`);
      if (trusted && gk && !spkiDer(trusted).equals(spkiDer(gk))) err(line, 'TRUSTED_KEY_MISMATCH', `${label}: genesis key differs from the trusted key`);
      if (!chainKey) chainKey = gk;
    }

    // a record of an unknown version cannot be hashed or checked; with no key at all the signature cannot be checked
    if (!unsupported) {
      const { hash, sig, ...body } = rec;
      if (!isHex(hash, 64) || sha256(canon(body)) !== hash) {
        err(line, 'HASH_MISMATCH', `${label}: content does not match its hash (record edited)`);
      }
      if (chainKey) {
        let good = false;
        try {
          const raw = Buffer.from(String(sig), 'base64');
          good = raw.length === 64 && crypto.verify(null, Buffer.from(String(hash), 'hex'), chainKey, raw);
        } catch { good = false; }
        if (!good) err(line, 'BAD_SIGNATURE', `${label}: signature does not verify`);
      }
    }

    prev = rec.hash;
    expectSeq = Number.isInteger(rec.seq) ? rec.seq + 1 : expectSeq + 1;
    out.head = { seq: rec.seq, hash: rec.hash };
  }

  if (out.records === 0 && !out.errors.length) err(0, 'EMPTY_LEDGER', 'the ledger has no records');

  for (const a of anchors) {
    if (!a || bySeq.get(a.seq) !== a.hash) err(0, 'ANCHOR_MISMATCH', `anchor at seq ${a && a.seq} does not match the ledger (truncated or rewritten)`);
  }

  if (store) checkBlobs(parsed, store, purged, out, warn, err);
  return out;
}

// ---- level 2 ----
function checkBlobs(parsed, store, purged, out, warn, err) {
  const erased = new Set();
  const keyCache = new Map();
  const dataKey = (kid) => {
    if (!keyCache.has(kid)) { let k = null; try { k = store.dataKey(kid); } catch { k = undefined; } keyCache.set(kid, k); }
    return keyCache.get(kid);
  };
  for (const [line, rec] of parsed) {
    for (const f of BLOB_FIELDS) {
      const digest = rec[f];
      if (!digest) continue;
      if (rec.key && purged.has(rec.key)) { erased.add(rec.key); continue; } // expected erasure
      const file = store.blob(rec.key, digest);
      if (!file) { warn(line, 'BLOB_MISSING', `seq ${rec.seq}: ${f} blob not found`); continue; }
      let plain = file;
      if (isSealed(file)) {
        const k = dataKey(file.subarray(4, 12).toString('hex'));
        if (k === null && !store.haveKeys) continue; // no key material given: level 1 for this blob
        if (k === null) { warn(line, 'KEY_MISSING', `seq ${rec.seq}: session key not available and not purged`); continue; }
        try { plain = openSealed(k, file); } catch { err(line, 'BLOB_CHANGED', `seq ${rec.seq}: ${f} blob content changed (decryption failed)`); continue; }
      }
      if (sha256(plain) !== digest) err(line, 'BLOB_CHANGED', `seq ${rec.seq}: ${f} blob content changed`);
    }
  }
  out.erased_keys = [...erased].sort();
}

// ---- command line ----
function main(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (['--key', '--anchor', '--blobs', '--keys', '--master-key'].includes(a)) args[a.slice(2)] = argv[++i];
    else if (a === '-h' || a === '--help') args.help = true;
    else args._.push(a);
  }
  if (args.help || args._.length !== 1) {
    process.stderr.write('usage: bb-verify.js LEDGER [--key PUBKEY.pem] [--anchor FILE] [--blobs DIR [--keys DIR] [--master-key HEX]] [--json]\n');
    return args.help ? 0 : 2;
  }
  let text;
  try { text = fs.readFileSync(args._[0], 'utf8'); } catch (e) { process.stderr.write(`cannot read ${args._[0]}: ${e.code || e.message}\n`); return 2; }
  const opts = {};
  try {
    if (args.key) opts.trustedKey = fs.readFileSync(args.key, 'utf8');
    if (args.anchor) opts.anchors = fs.readFileSync(args.anchor, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch (e) { process.stderr.write(`cannot read an input file: ${e.message}\n`); return 2; }
  if (args.blobs) opts.store = fsStore({ blobs: args.blobs, keys: args.keys, masterKey: args['master-key'] });

  const r = verifyLedger(text, opts);
  if (args.json) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
  else {
    for (const e of r.errors) process.stdout.write(`error   line ${e.line}  ${e.code}  ${e.message}\n`);
    for (const w of r.warnings) process.stdout.write(`warning line ${w.line}  ${w.code}  ${w.message}\n`);
    const head = r.head ? `head #${r.head.seq} ${r.head.hash}` : 'no head';
    process.stdout.write(`${r.ok ? 'PASS' : 'FAIL'}  ${r.records} records, ${head}, level ${r.level}${r.erased_keys.length ? `, ${r.erased_keys.length} erased key(s)` : ''}\n`);
    if (r.ok && !opts.trustedKey) process.stdout.write('note: no --key given, so the chain is only checked against the key in its own genesis record\n');
    if (r.ok && !opts.anchors) process.stdout.write('note: no --anchor given, so cutting off the last records would not be noticed\n');
  }
  return r.ok ? 0 : 1;
}

module.exports = { verifyLedger, fsStore, canon, parseStrict };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
