# Test vectors for the ledger format v1

Files that any implementation of [ledger-v1](../ledger-v1.md) can check itself
against, in any language.

- `canonical.json`: JSON text, its canonical form (section 4) and the SHA-256
  of that form. Run your canonicalizer over `json` and compare.
- `manifest.json`: one entry per case under `cases/`, with the inputs a
  verifier needs and what it must report.
- `cases/<name>/ledger.jsonl`: the ledger. Level 2 cases also have `blobs/`
  and `keys/` (`keys/master.key` is hex; `keys/sessions/<kid>.key` are the
  wrapped data keys of section 8). Anchor cases have `anchor.json`.
- `key.pub.pem`: the signer's public key, for the cases that name a
  `trusted_key`.
- `generate.js`: builds all of the above with nothing but Node's `crypto`
  and the rules of the spec. Keys are derived from fixed strings, so output
  is byte for byte reproducible (`node docs/spec/vectors/generate.js` leaves
  the tree unchanged). The keys are for testing only and have no other use.

## What a case says

```json
{
  "name": "invalid-removed-record",
  "level": 1,
  "ledger": "cases/invalid-removed-record/ledger.jsonl",
  "trusted_key": "key.pub.pem",        // optional: give this key to the verifier
  "anchor": "cases/.../anchor.json",   // optional: check the ledger against it
  "blobs": "...", "keys": "...",       // level 2 only
  "expect": {
    "ok": false,
    "records": 8,
    "head": { "seq": 9, "hash": "..." },          // not present on invalid cases
    "errors": [{ "line": 4, "code": "SEQ_GAP" }, { "line": 4, "code": "PREV_MISMATCH" }],
    "warnings": [],
    "erased_keys": []                              // level 2 only
  }
}
```

A verifier conforms to level N when, for every case of level N or lower, it
reports the same `ok`, the same list of `(line, code)` errors and warnings
(order does not matter) and, for valid cases, the same `records` and `head`.
Codes are defined in section 11 of the spec.

## Regenerating

Change `generate.js`, run it, and review the diff of the vectors. A change in
an existing vector's bytes is a change in the format and needs a spec change.
