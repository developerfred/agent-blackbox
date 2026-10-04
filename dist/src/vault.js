'use strict';
// Encryption at rest for payload blobs, with one data key per session.
//
// Each session (or, for records with no session, each month) gets its own
// random 256-bit data key. Data keys are stored wrapped (AES-256-GCM) under a
// master key, and every blob is sealed with AES-256-GCM under its session key.
// Deleting a session's wrapped key makes all of that session's payloads
// unreadable forever (crypto-erasure), even in backups and file-sync copies
// made earlier, while the hash chain keeps every record and stays verifiable.
//
// What this protects: copies of ~/.blackbox (backups, Time Machine, cloud sync,
// another tool that indexes your disk) and selective erasure. What it does not:
// a process running as the same OS user can read the master key too. Running
// the recorder as a dedicated user (`blackbox harden`) closes that gap.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const MAGIC = Buffer.from('BBX1');
const KID_BYTES = 8;
const HEADER = MAGIC.length + KID_BYTES + 12 + 16;
class KeyErased extends Error {
    /** @param {string} kid */
    constructor(kid) { super(`key ${kid} was erased`); this.code = 'ERASED'; this.kid = kid; }
}
/** @param {Buffer} key @param {Buffer} plain @param {Buffer} aad */
function aesSeal(key, plain, aad) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(aad);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    return { iv, tag: c.getAuthTag(), ct };
}
/** @param {Buffer} key @param {Buffer} iv @param {Buffer} tag @param {Buffer} ct @param {Buffer} aad */
function aesOpen(key, iv, tag, ct, aad) {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(aad);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
}
// Overwrite before unlinking. On SSDs and copy-on-write filesystems this is
// not a guarantee, which is why the key is small and wrapped: what matters is
// that no copy of the unwrapped key ever touches the disk.
/** @param {string} file */
function shred(file) {
    try {
        const { size } = fs.statSync(file);
        fs.writeFileSync(file, crypto.randomBytes(size));
        fs.unlinkSync(file);
        return true;
    }
    catch {
        return false;
    }
}
class Vault {
    /** @param {{ keysDir: string, masterKey?: string }} opts */
    constructor({ keysDir, masterKey }) {
        this.dir = path.join(keysDir, 'sessions');
        this.masterFile = path.join(keysDir, 'master.key');
        fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        this.master = masterKey ? Buffer.from(masterKey, 'hex') : this.loadOrCreateMaster();
        if (this.master.length !== 32)
            throw new Error('master key must be 32 bytes');
        this.cache = new Map();
    }
    loadOrCreateMaster() {
        if (process.env.BLACKBOX_MASTER_KEY)
            return Buffer.from(process.env.BLACKBOX_MASTER_KEY, 'hex');
        if (!fs.existsSync(this.masterFile)) {
            fs.writeFileSync(this.masterFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
        }
        return Buffer.from(fs.readFileSync(this.masterFile, 'utf8').trim(), 'hex');
    }
    // The key id is derived from the scope with the master key, so file names
    // in keys/sessions and blobs/ do not reveal session ids.
    /** @param {string} scope */
    kid(scope) {
        return crypto.createHmac('sha256', this.master).update('kid:' + scope).digest('hex').slice(0, KID_BYTES * 2);
    }
    /** @param {string} kid */
    keyFile(kid) { return path.join(this.dir, `${kid}.key`); }
    /** @param {string} kid @param {boolean} [create] @returns {Buffer} */
    dataKey(kid, create) {
        if (this.cache.has(kid))
            return this.cache.get(kid);
        const f = this.keyFile(kid);
        let key;
        if (fs.existsSync(f)) {
            const b = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'base64');
            key = aesOpen(this.master, b.subarray(0, 12), b.subarray(12, 28), b.subarray(28), Buffer.from('wrap:' + kid));
        }
        else if (create) {
            key = crypto.randomBytes(32);
            const w = aesSeal(this.master, key, Buffer.from('wrap:' + kid));
            fs.writeFileSync(f, Buffer.concat([w.iv, w.tag, w.ct]).toString('base64'), { mode: 0o600 });
        }
        else {
            throw new KeyErased(kid);
        }
        this.cache.set(kid, key);
        return key;
    }
    /** @param {string} scope @param {Buffer} plain @returns {{ kid: string, data: Buffer }} */
    seal(scope, plain) {
        const kid = this.kid(scope);
        const key = this.dataKey(kid, true);
        const kidBuf = Buffer.from(kid, 'hex');
        const aad = Buffer.concat([MAGIC, kidBuf]);
        const { iv, tag, ct } = aesSeal(key, plain, aad);
        return { kid, data: Buffer.concat([MAGIC, kidBuf, iv, tag, ct]) };
    }
    // Throws KeyErased if the session key is gone, or an auth error if the
    // ciphertext was altered.
    /** @param {Buffer} sealed @returns {Buffer} */
    open(sealed) {
        if (!Vault.isSealed(sealed))
            return sealed;
        const kidBuf = sealed.subarray(MAGIC.length, MAGIC.length + KID_BYTES);
        const kid = kidBuf.toString('hex');
        const iv = sealed.subarray(MAGIC.length + KID_BYTES, MAGIC.length + KID_BYTES + 12);
        const tag = sealed.subarray(MAGIC.length + KID_BYTES + 12, HEADER);
        return aesOpen(this.dataKey(kid, false), iv, tag, sealed.subarray(HEADER), Buffer.concat([MAGIC, kidBuf]));
    }
    /** @param {string} kid */
    hasKey(kid) { return this.cache.has(kid) || fs.existsSync(this.keyFile(kid)); }
    /** @param {string} kid */
    erase(kid) {
        this.cache.delete(kid);
        return shred(this.keyFile(kid));
    }
    /** @param {Buffer} buf */
    static isSealed(buf) { return buf.length >= HEADER && buf.subarray(0, MAGIC.length).equals(MAGIC); }
}
// The scope that decides which key protects a record's payloads.
/** @param {string | undefined | null} sessionId @param {Date | string | number} [ts] */
function scopeOf(sessionId, ts = new Date()) {
    return sessionId ? `session:${sessionId}` : `month:${new Date(ts).toISOString().slice(0, 7)}`;
}
module.exports = { Vault, KeyErased, scopeOf, shred };
