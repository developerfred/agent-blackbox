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
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const MAGIC = Buffer.from('BBX1');
const KID_BYTES = 8;
const HEADER = MAGIC.length + KID_BYTES + 12 + 16;

export class KeyErased extends Error {
  code: string;
  kid: string;
  constructor(kid: string) { super(`key ${kid} was erased`); this.code = 'ERASED'; this.kid = kid; }
}

function aesSeal(key: Buffer, plain: Buffer, aad: Buffer): { iv: Buffer; tag: Buffer; ct: Buffer } {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { iv, tag: c.getAuthTag(), ct };
}

function aesOpen(key: Buffer, iv: Buffer, tag: Buffer, ct: Buffer, aad: Buffer): Buffer {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Overwrite before unlinking. On SSDs and copy-on-write filesystems this is
// not a guarantee, which is why the key is small and wrapped: what matters is
// that no copy of the unwrapped key ever touches the disk.
export function shred(file: string): boolean {
  try {
    const { size } = fs.statSync(file);
    fs.writeFileSync(file, crypto.randomBytes(size));
    fs.unlinkSync(file);
    return true;
  } catch { return false; }
}

export class Vault {
  dir: string;
  masterFile: string;
  master: Buffer;
  cache: Map<string, Buffer>;

  constructor({ keysDir, masterKey }: { keysDir: string; masterKey?: string }) {
    this.dir = path.join(keysDir, 'sessions');
    this.masterFile = path.join(keysDir, 'master.key');
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    this.master = masterKey ? Buffer.from(masterKey, 'hex') : this.loadOrCreateMaster();
    if (this.master.length !== 32) throw new Error('master key must be 32 bytes');
    this.cache = new Map<string, Buffer>();
  }

  loadOrCreateMaster(): Buffer {
    if (process.env.BLACKBOX_MASTER_KEY) return Buffer.from(process.env.BLACKBOX_MASTER_KEY, 'hex');
    if (!fs.existsSync(this.masterFile)) {
      fs.writeFileSync(this.masterFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
    }
    return Buffer.from(fs.readFileSync(this.masterFile, 'utf8').trim(), 'hex');
  }

  // The key id is derived from the scope with the master key, so file names
  // in keys/sessions and blobs/ do not reveal session ids.
  kid(scope: string): string {
    return crypto.createHmac('sha256', this.master).update('kid:' + scope).digest('hex').slice(0, KID_BYTES * 2);
  }

  keyFile(kid: string): string { return path.join(this.dir, `${kid}.key`); }

  dataKey(kid: string, create?: boolean): Buffer {
    const hit = this.cache.get(kid);
    if (hit) return hit;
    const f = this.keyFile(kid);
    let key: Buffer;
    if (fs.existsSync(f)) {
      const b = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'base64');
      key = aesOpen(this.master, b.subarray(0, 12), b.subarray(12, 28), b.subarray(28), Buffer.from('wrap:' + kid));
    } else if (create) {
      key = crypto.randomBytes(32);
      const w = aesSeal(this.master, key, Buffer.from('wrap:' + kid));
      fs.writeFileSync(f, Buffer.concat([w.iv, w.tag, w.ct]).toString('base64'), { mode: 0o600 });
    } else {
      throw new KeyErased(kid);
    }
    this.cache.set(kid, key);
    return key;
  }

  seal(scope: string, plain: Buffer): { kid: string; data: Buffer } {
    const kid = this.kid(scope);
    const key = this.dataKey(kid, true);
    const kidBuf = Buffer.from(kid, 'hex');
    const aad = Buffer.concat([MAGIC, kidBuf]);
    const { iv, tag, ct } = aesSeal(key, plain, aad);
    return { kid, data: Buffer.concat([MAGIC, kidBuf, iv, tag, ct]) };
  }

  // Throws KeyErased if the session key is gone, or an auth error if the
  // ciphertext was altered.
  open(sealed: Buffer): Buffer {
    if (!Vault.isSealed(sealed)) return sealed;
    const kidBuf = sealed.subarray(MAGIC.length, MAGIC.length + KID_BYTES);
    const kid = kidBuf.toString('hex');
    const iv = sealed.subarray(MAGIC.length + KID_BYTES, MAGIC.length + KID_BYTES + 12);
    const tag = sealed.subarray(MAGIC.length + KID_BYTES + 12, HEADER);
    return aesOpen(this.dataKey(kid, false), iv, tag, sealed.subarray(HEADER), Buffer.concat([MAGIC, kidBuf]));
  }

  hasKey(kid: string): boolean { return this.cache.has(kid) || fs.existsSync(this.keyFile(kid)); }

  erase(kid: string): boolean {
    this.cache.delete(kid);
    return shred(this.keyFile(kid));
  }

  static isSealed(buf: Buffer): boolean { return buf.length >= HEADER && buf.subarray(0, MAGIC.length).equals(MAGIC); }
}

// The scope that decides which key protects a record's payloads.
export function scopeOf(sessionId: string | undefined | null, ts: Date | string | number = new Date()): string {
  return sessionId ? `session:${sessionId}` : `month:${new Date(ts).toISOString().slice(0, 7)}`;
}
