# Anchoring the chain head

A hash chain proves nothing was changed *inside* the ledger. It cannot show that the last records were cut off, or that someone with the signing key re-signed the whole chain. For that you publish the chain head somewhere the agent cannot write (a git commit, a gist, a transparency log). Anyone can then compare it with the ledger.

## Batches and Merkle roots

`blackbox anchor --batch` commits to every record since the previous anchor with one Merkle root and writes it into the ledger as an `anchor` record. Publish the printed `seq`, `hash` and `root`.

The tree is the one from RFC 6962 (Certificate Transparency): leaf = SHA-256(`0x00` || record hash bytes), node = SHA-256(`0x01` || left || right). The same code is in `src/merkle.js`, with no dependencies.

Why a root and not only the head: a single record can be proven to belong to the batch with about log2(n) hashes, without handing over the other records.

```
blackbox anchor --prove 42 > proof.json     # needs the ledger
blackbox anchor --verify-proof proof.json   # needs only proof.json and the root you published
```

## The `anchor` record (optional addition, `v` stays 1)

| field | meaning |
|---|---|
| `alg` | `merkle-sha256-rfc6962` |
| `from`, `to` | first and last record covered; `to` is below this record's `seq` |
| `count` | `to - from + 1` |
| `root` | hex Merkle root over the `hash` of records `from..to` |

`blackbox verify` recomputes the root and fails on a mismatch, an unknown `alg`, or a range that does not fit. A proof does not bind the batch size, so a verifier takes `from`, `to` and `count` from the signed anchor record, never from the proof.

## What this does not do (yet)

Writing the anchor record only makes the ledger commit to the batch; trust comes from publishing the root outside it. `blackbox anchor --batch` does not send anything anywhere. Scheduled batches and an optional publishing target come in a separate, opt-in change.
