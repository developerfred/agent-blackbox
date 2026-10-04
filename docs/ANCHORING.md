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

## Automatic anchoring (opt-in)

Off by default. Turn it on by naming a target:

```
blackbox anchor --auto --file ~/synced/anchors.jsonl          # append a line per batch
blackbox anchor --auto --webhook https://example.org/anchors  # POST the same JSON
blackbox anchor --auto --file ... --every 100 --minutes 60    # when a batch is due
blackbox anchor --auto            # show the setting
blackbox anchor --auto off
```

The recorder then commits a batch when `every` new records have piled up (default 100), or when there is at least one new record and `minutes` have passed since the last batch (default 60), and publishes it. A failed publish is kept and retried each minute. The setting lives in `config.anchor` (`file`, `webhook`, `every`, `minutes`); with the recorder as its own user, an admin sets it in the recorder's `config.json`.

What leaves the machine: `seq`, `hash`, `sig` and `key_id` of the anchor record, its `from`, `to`, `count`, `root`, and the time. No payload, summary, session id, path or prompt. Nothing is sent when `anchor` is not configured.

Choose the target with care: an anchor only protects you if the agent cannot rewrite where it was published. A file in a folder the agent can write is no better than the ledger itself; a git remote, a synced folder the agent cannot reach, or a service you control is.

## What this does not do

It does not pick a public transparency log or timestamp authority for you, and it does not prove that everything was recorded (see the spec, section 11). RFC 3161 timestamping and OpenTimestamps targets are possible later targets.
