"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.blobPath = exports.Ledger = exports.GENESIS = exports.sha256 = void 0;
exports.canon = canon;
exports.verify = verify;
// Append-only, hash-chained, Ed25519-signed evidence ledger.
// Each line is one record. hash = sha256(canonical(record without hash/sig)),
// sig = Ed25519(hash). Payloads live in a content-addressed blob store; the
// record only carries their sha256, so content can be crypto-erased later
// without breaking the chain.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const util_1 = require("./util");
Object.defineProperty(exports, "sha256", { enumerable: true, get: function () { return util_1.sha256; } });
const merkle_1 = require("./merkle");
exports.GENESIS = '0'.repeat(64);
/** Canonical JSON: sorted keys, no undefined, so a record always hashes the same. */
function canon(v) {
    if (v === null || typeof v !== 'object')
        return JSON.stringify(v === undefined ? null : v);
    if (Array.isArray(v))
        return '[' + v.map(canon).join(',') + ']';
    const o = v;
    return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort()
        .map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}
function loadOrCreateKeys(P) {
    if (!fs.existsSync(P.privKey)) {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
        fs.writeFileSync(P.privKey, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
        fs.writeFileSync(P.pubKey, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    }
    const priv = crypto.createPrivateKey(fs.readFileSync(P.privKey));
    const pubPem = fs.readFileSync(P.pubKey, 'utf8');
    const pub = crypto.createPublicKey(pubPem);
    const keyId = (0, util_1.sha256)(pub.export({ type: 'spki', format: 'der' })).slice(0, 16);
    return { priv, pub, pubPem, keyId };
}
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
    seq = 0;
    head = exports.GENESIS;
    last = null;
    /** bytes written so far */
    size = 0;
    P;
    vault;
    keys;
    // vault (optional): a Vault; when set, payload blobs are sealed with the key
    // of their session and stored under blobs/<kid>/<sha>.
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
            this.head = exports.GENESIS;
            this.append('genesis', { key_id: this.keys.keyId, public_key: this.keys.pubPem });
        }
    }
    // Store content by its hash; returns the digest recorded in the chain (the
    // sha256 of the plaintext) and, when encrypted, the id of the key used.
    putBlob(content, scope = null) {
        const buf = Buffer.isBuffer(content) ? content
            : Buffer.from(typeof content === 'string' ? content : canon(content));
        const digest = (0, util_1.sha256)(buf);
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
    getBlob(sha, kid) {
        const file = (0, exports.blobPath)(this.P.blobs, sha, kid);
        const raw = fs.readFileSync(file);
        return this.vault ? this.vault.open(raw) : raw;
    }
    // Move a file into the blob store (used for raw API bodies).
    adoptFile(src) {
        const buf = fs.readFileSync(src);
        const digest = (0, util_1.sha256)(buf);
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
    append(kind, fields) {
        const rec = { v: 1, seq: this.seq + 1, ts: new Date().toISOString(), kind, ...fields, prev: this.head };
        const hash = (0, util_1.sha256)(canon(rec));
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
exports.Ledger = Ledger;
const BLOB_FIELDS = ['payload', 'request_blob', 'response_blob'];
// Does a line of valid JSON repeat a key inside one object? JSON.parse keeps
// the last value silently, so two readers of the same line could disagree.
function hasDuplicateKeys(text) {
    const stack = [];
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        const top = stack[stack.length - 1];
        if (c === '"') {
            let j = i + 1;
            while (text[j] !== '"')
                j += text[j] === '\\' ? 2 : 1;
            if (top && top.keys && top.expectKey) {
                const k = JSON.parse(text.slice(i, j + 1));
                if (top.keys.has(k))
                    return true;
                top.keys.add(k);
                top.expectKey = false;
            }
            i = j;
        }
        else if (c === '{')
            stack.push({ keys: new Set(), expectKey: true });
        else if (c === '[')
            stack.push({ keys: null, expectKey: false });
        else if (c === '}' || c === ']')
            stack.pop();
        else if (c === ',' && top && top.keys)
            top.expectKey = true;
    }
    return false;
}
const blobPath = (dir, sha, kid) => (kid ? path.join(dir, kid, sha) : path.join(dir, sha));
exports.blobPath = blobPath;
function verify({ ledgerPath, pubPem, blobsDir, vault = null }) {
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
        for (const k of ((0, util_1.parseLine)(l) || {}).erased_keys || [])
            purgedKeys.add(k);
    }
    const pub = pubPem ? crypto.createPublicKey(pubPem) : null;
    let prev = exports.GENESIS;
    let expectSeq = 1;
    let chainPub = pub;
    /** record hashes by position, for checking anchor batches */
    const hashes = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line)
            continue;
        // codes are those of docs/spec/ledger-v1.md, section 11
        const fail = (problem, code) => { out.ok = false; out.errors.push({ line: i + 1, problem, code }); };
        const rec = (0, util_1.parseLine)(line);
        if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
            fail('not valid JSON', 'INVALID_JSON');
            continue;
        }
        if (hasDuplicateKeys(line))
            fail('a key appears twice in the record', 'DUPLICATE_KEY');
        const first = out.records === 0;
        out.records++;
        const { hash, sig, ...body } = rec;
        const unsupported = rec.v !== 1;
        if (unsupported)
            fail(`seq ${rec.seq}: record version ${JSON.stringify(rec.v)} is not supported`, 'UNSUPPORTED_VERSION');
        if (rec.seq !== expectSeq)
            fail(`sequence gap: expected ${expectSeq}, found ${rec.seq}`, 'SEQ_GAP');
        if (rec.prev !== prev)
            fail(`seq ${rec.seq}: prev does not match the previous record's hash (record removed, inserted or reordered)`, 'PREV_MISMATCH');
        if (first && rec.kind !== 'genesis')
            fail(`seq ${rec.seq}: the first record must be genesis`, 'GENESIS_REQUIRED');
        if (!first && rec.kind === 'genesis')
            fail(`seq ${rec.seq}: only the first record may be genesis`, 'GENESIS_DUPLICATE');
        if (first && rec.kind === 'genesis') {
            let gpub = null;
            try {
                gpub = crypto.createPublicKey(rec.public_key);
            }
            catch { /* reported below */ }
            if (!gpub || (0, util_1.sha256)(gpub.export({ type: 'spki', format: 'der' })).slice(0, 16) !== rec.key_id) {
                fail(`seq ${rec.seq}: key_id does not match public_key`, 'KEY_ID_MISMATCH');
            }
            if (pub && gpub && pub.export({ type: 'spki', format: 'der' }).compare(gpub.export({ type: 'spki', format: 'der' })) !== 0) {
                fail('genesis key differs from the trusted public key (chain rewritten with another key)', 'TRUSTED_KEY_MISMATCH');
            }
            chainPub = pub || gpub;
        }
        // a record of an unknown version cannot be hashed or signed by these rules
        if (!unsupported) {
            if ((0, util_1.sha256)(canon(body)) !== hash)
                fail(`seq ${rec.seq}: content does not match its hash (record edited)`, 'HASH_MISMATCH');
            // with no key at all (no genesis, no trusted key) the signature cannot be checked
            if (chainPub) {
                let good = false;
                try {
                    const raw = Buffer.from(String(sig), 'base64');
                    good = raw.length === 64 && crypto.verify(null, Buffer.from(String(hash), 'hex'), chainPub, raw);
                }
                catch {
                    good = false;
                }
                if (!good)
                    fail(`seq ${rec.seq}: bad signature`, 'BAD_SIGNATURE');
            }
        }
        for (const f of BLOB_FIELDS) {
            const d = rec[f];
            if (!d)
                continue;
            const file = (0, exports.blobPath)(blobsDir, d, rec.key);
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
                if ((0, util_1.sha256)(plain) !== d)
                    fail(`seq ${rec.seq}: ${f} blob content changed`);
            }
            else if ((0, util_1.sha256)(fs.readFileSync(file)) !== d)
                fail(`seq ${rec.seq}: ${f} blob content changed`);
        }
        if (rec.kind === 'anchor') {
            // a batch root must cover exactly the records it names
            const ok = rec.alg === merkle_1.MERKLE_ALG && Number.isInteger(rec.from) && Number.isInteger(rec.to)
                && rec.from >= 1 && rec.to >= rec.from && rec.to < rec.seq && rec.count === rec.to - rec.from + 1;
            if (!ok)
                fail(`seq ${rec.seq}: anchor record is malformed or uses an unknown algorithm`);
            else if ((0, merkle_1.merkleRoot)(hashes.slice(rec.from - 1, rec.to)) !== rec.root)
                fail(`seq ${rec.seq}: anchor root does not match records ${rec.from}..${rec.to}`);
        }
        hashes.push(hash);
        if (rec.session_id)
            sessions.add(rec.session_id);
        prev = hash;
        expectSeq = rec.seq + 1;
        out.head = { seq: rec.seq, hash };
    }
    if (!out.records && !out.errors.length) {
        out.ok = false;
        out.errors.push({ line: 0, problem: 'the ledger has no records', code: 'EMPTY_LEDGER' });
    }
    out.sessions = sessions.size;
    return out;
}
