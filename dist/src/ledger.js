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
/** Canonical JSON: sorted keys, no undefined, so a record always hashes the same.
 * @param {unknown} v @returns {string} */
function canon(v) {
    if (v === null || typeof v !== 'object')
        return JSON.stringify(v === undefined ? null : v);
    if (Array.isArray(v))
        return '[' + v.map(canon).join(',') + ']';
    const o = /** @type {Record<string, unknown>} */ (v);
    return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort()
        .map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}
const { sha256, parseLine } = require('./util');
const { merkleRoot, MERKLE_ALG } = require('./merkle');
/** @param {import('./types').Paths} P */
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
/** @param {string} file @returns {string | null} */
function readLastLine(file) {
    if (!fs.existsSync(file))
        return null;
    const size = fs.statSync(file).size;
    if (!size)
        return null;
    const len = Math.min(size, 1 << 20);
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, size - len);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n').filter(Boolean);
    return lines.length ? lines[lines.length - 1] : null;
}
class Ledger {
    /** @type {number} */ seq = 0;
    /** @type {string} */ head = GENESIS;
    /** @type {import('./types').LedgerRecord | null} */ last = null;
    /** bytes written so far @type {number} */ size = 0;
    // vault (optional): a Vault; when set, payload blobs are sealed with the key
    // of their session and stored under blobs/<kid>/<sha>.
    /** @param {import('./types').Paths} P @param {{ vault?: import('./vault').Vault | null }} [opts] */
    constructor(P, { vault = null } = {}) {
        this.P = P;
        this.vault = vault;
        this.keys = loadOrCreateKeys(P);
        this.size = fs.existsSync(P.ledger) ? fs.statSync(P.ledger).size : 0; // bytes written so far
        const last = readLastLine(P.ledger);
        if (last) {
            const rec = JSON.parse(last);
            this.seq = rec.seq;
            this.head = rec.hash;
            this.last = rec;
        }
        else {
            this.seq = 0;
            this.head = GENESIS;
            this.append('genesis', { key_id: this.keys.keyId, public_key: this.keys.pubPem });
        }
    }
    // Store content by its hash; returns the digest recorded in the chain (the
    // sha256 of the plaintext) and, when encrypted, the id of the key used.
    /** @param {unknown} content @param {string | null} [scope] */
    putBlob(content, scope = null) {
        const buf = Buffer.isBuffer(content) ? content
            : Buffer.from(typeof content === 'string' ? content : canon(content));
        const digest = sha256(buf);
        if (this.vault && scope) {
            const kid = this.vault.kid(scope);
            const dir = path.join(this.P.blobs, kid);
            const file = path.join(dir, digest);
            if (!fs.existsSync(file)) {
                fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
                fs.writeFileSync(file, this.vault.seal(scope, buf).data, { mode: 0o600 });
            }
            return { sha: digest, size: buf.length, key: kid };
        }
        const file = path.join(this.P.blobs, digest);
        if (!fs.existsSync(file))
            fs.writeFileSync(file, buf, { mode: 0o600 });
        return { sha: digest, size: buf.length };
    }
    // Read a payload back (decrypting it if needed). Throws if it was erased.
    /** @param {string} sha @param {string} [kid] */
    getBlob(sha, kid) {
        const file = blobPath(this.P.blobs, sha, kid);
        const raw = fs.readFileSync(file);
        return this.vault ? this.vault.open(raw) : raw;
    }
    // Move a file into the blob store (used for raw API bodies).
    /** @param {string} src */
    adoptFile(src) {
        const buf = fs.readFileSync(src);
        const digest = sha256(buf);
        const file = path.join(this.P.blobs, digest);
        if (fs.existsSync(file))
            fs.unlinkSync(src);
        else
            fs.renameSync(src, file);
        try {
            fs.chmodSync(file, 0o600);
        }
        catch { /* best effort */ }
        return { sha: digest, size: buf.length };
    }
    /**
     * @param {string} kind
     * @param {Record<string, unknown>} fields
     * @returns {import('./types').LedgerRecord}
     */
    append(kind, fields) {
        const rec = { v: 1, seq: this.seq + 1, ts: new Date().toISOString(), kind, ...fields, prev: this.head };
        const hash = sha256(canon(rec));
        const sig = crypto.sign(null, Buffer.from(hash, 'hex'), this.keys.priv).toString('base64');
        const full = { ...rec, hash, sig };
        const line = JSON.stringify(full) + '\n';
        fs.appendFileSync(this.P.ledger, line, { mode: 0o600 });
        this.size += Buffer.byteLength(line);
        this.seq = rec.seq;
        this.head = hash;
        this.last = full;
        return full;
    }
}
const BLOB_FIELDS = ['payload', 'request_blob', 'response_blob'];
/** @param {string} dir @param {string} sha @param {string} [kid] */
const blobPath = (dir, sha, kid) => (kid ? path.join(dir, kid, sha) : path.join(dir, sha));
// Walk the whole chain. Integrity proves nothing recorded was changed,
// removed or reordered; it does not prove that everything was recorded.
// With a vault, encrypted payloads are decrypted and checked against their
// hash; without one (a third party checking the chain), they are counted as
// sealed and their content is not checked.
/**
 * @param {{ ledgerPath: string, pubPem?: string | null, blobsDir: string, vault?: import('./vault').Vault | null }} opts
 */
function verify({ ledgerPath, pubPem, blobsDir, vault = null }) {
    /** @type {{ ok: boolean, records: number, errors: { line: number, problem: string }[], warnings: string[], head: { seq: number, hash: string } | null, sessions: number, sealed: number, erasedKeys: number }} */
    const out = { ok: true, records: 0, errors: [], warnings: [], head: null, sessions: 0, sealed: 0, erasedKeys: 0 };
    const sessions = new Set();
    const erasedSeen = new Set();
    let text;
    try {
        text = fs.readFileSync(ledgerPath, 'utf8');
    }
    catch {
        out.ok = false;
        out.errors.push({ line: 0, problem: 'ledger not found' });
        return out;
    }
    const lines = text.split('\n');
    // purge records come after the records they erase, so look ahead once
    const purgedKeys = new Set();
    for (const l of lines) {
        if (!l.includes('"kind":"purge"'))
            continue;
        for (const k of (parseLine(l) || {}).erased_keys || [])
            purgedKeys.add(k);
    }
    const pub = pubPem ? crypto.createPublicKey(pubPem) : null;
    let prev = GENESIS;
    let expectSeq = 1;
    let chainPub = pub;
    /** record hashes by position, for checking anchor batches @type {string[]} */
    const hashes = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line)
            continue;
        /** @param {string} problem */
        const fail = (problem) => { out.ok = false; out.errors.push({ line: i + 1, problem }); };
        const rec = parseLine(line);
        if (!rec) {
            fail('not valid JSON');
            continue;
        }
        out.records++;
        const { hash, sig, ...body } = rec;
        if (rec.seq !== expectSeq)
            fail(`sequence gap: expected ${expectSeq}, found ${rec.seq}`);
        if (rec.prev !== prev)
            fail(`seq ${rec.seq}: prev does not match the previous record's hash (record removed, inserted or reordered)`);
        if (sha256(canon(body)) !== hash)
            fail(`seq ${rec.seq}: content does not match its hash (record edited)`);
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
        }
        catch {
            fail(`seq ${rec.seq}: unreadable signature`);
        }
        for (const f of BLOB_FIELDS) {
            const d = rec[f];
            if (!d)
                continue;
            const file = blobPath(blobsDir, d, rec.key);
            // erased keys are known from the vault, or from the signed purge records
            if (rec.key && ((vault && !vault.hasKey(rec.key)) || purgedKeys.has(rec.key))) {
                // crypto-erased: the key is gone, so the content is unrecoverable by design
                if (!erasedSeen.has(rec.key)) {
                    erasedSeen.add(rec.key);
                    out.erasedKeys++;
                }
                continue;
            }
            if (!fs.existsSync(file)) {
                out.warnings.push(`seq ${rec.seq}: ${f} blob missing (erased or not copied)`);
                continue;
            }
            if (rec.key) {
                if (!vault) {
                    out.sealed++;
                    continue;
                }
                let plain;
                try {
                    plain = vault.open(fs.readFileSync(file));
                }
                catch {
                    fail(`seq ${rec.seq}: ${f} blob content changed (decryption failed)`);
                    continue;
                }
                if (sha256(plain) !== d)
                    fail(`seq ${rec.seq}: ${f} blob content changed`);
            }
            else if (sha256(fs.readFileSync(file)) !== d)
                fail(`seq ${rec.seq}: ${f} blob content changed`);
        }
        if (rec.kind === 'anchor') {
            // a batch root must cover exactly the records it names
            const ok = rec.alg === MERKLE_ALG && Number.isInteger(rec.from) && Number.isInteger(rec.to)
                && rec.from >= 1 && rec.to >= rec.from && rec.to < rec.seq && rec.count === rec.to - rec.from + 1;
            if (!ok)
                fail(`seq ${rec.seq}: anchor record is malformed or uses an unknown algorithm`);
            else if (merkleRoot(hashes.slice(rec.from - 1, rec.to)) !== rec.root)
                fail(`seq ${rec.seq}: anchor root does not match records ${rec.from}..${rec.to}`);
        }
        hashes.push(hash);
        if (rec.session_id)
            sessions.add(rec.session_id);
        prev = hash;
        expectSeq = rec.seq + 1;
        out.head = { seq: rec.seq, hash };
    }
    out.sessions = sessions.size;
    return out;
}
module.exports = { Ledger, verify, canon, sha256, blobPath, GENESIS };
