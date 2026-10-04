'use strict';
// Merkle tree over ledger record hashes, as in RFC 6962 (Certificate
// Transparency): leaf = SHA-256(0x00 || h), node = SHA-256(0x01 || left || right),
// where h is the 32 raw bytes of a record's `hash`. An anchor then commits to a
// whole batch of records with one root, and one record can be proven to be in
// the batch with log2(n) hashes, without revealing the others.
const crypto = require('crypto');

const sha = (/** @type {Buffer[]} */ ...parts) => {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);

/** @param {string} hex */
const leafHash = (hex) => sha(LEAF, Buffer.from(hex, 'hex'));

/** Largest power of two strictly below n (n >= 2). @param {number} n */
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** @param {Buffer[]} leaves @returns {Buffer} */
function mth(leaves) {
  if (leaves.length === 0) return sha();
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return sha(NODE, mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

/** Root over record hashes (hex), as hex. @param {string[]} hashes */
const merkleRoot = (hashes) => mth(hashes.map(leafHash)).toString('hex');

/**
 * Audit path for the record at `index`: sibling hashes from the leaf up.
 * @param {string[]} hashes @param {number} index @returns {string[]}
 */
function merkleProof(hashes, index) {
  if (!(index >= 0 && index < hashes.length)) throw new RangeError('index outside the batch');
  /** @param {Buffer[]} leaves @param {number} i @returns {Buffer[]} */
  const path = (leaves, i) => {
    if (leaves.length <= 1) return [];
    const k = split(leaves.length);
    return i < k ? [...path(leaves.slice(0, k), i), mth(leaves.slice(k))]
      : [...path(leaves.slice(k), i - k), mth(leaves.slice(0, k))];
  };
  return path(hashes.map(leafHash), index).map((b) => b.toString('hex'));
}

/**
 * Recompute the root from one record hash and its path (RFC 9162 2.1.3.2).
 * @param {{ hash: string, index: number, size: number, proof: string[], root: string }} p
 */
function verifyProof({ hash, index, size, proof, root }) {
  if (!(index >= 0 && index < size)) return false;
  let fn = index;
  let sn = size - 1;
  let r = leafHash(hash);
  for (const hex of proof) {
    if (sn === 0) return false;
    const p = Buffer.from(hex, 'hex');
    if (fn % 2 === 1 || fn === sn) {
      r = sha(NODE, p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = sha(NODE, r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r.toString('hex') === root;
}

/** Value of the `alg` field of an `anchor` record. */
const MERKLE_ALG = 'merkle-sha256-rfc6962';

module.exports = { MERKLE_ALG, merkleRoot, merkleProof, verifyProof, leafHash };
