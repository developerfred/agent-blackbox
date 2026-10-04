# bb-verify

A standalone verifier for the agent-blackbox [ledger format v1](../docs/spec/ledger-v1.md).
One file, no dependencies, Node 18 or later. It shares no code with the
recorder, so it can be copied to a machine that has only the ledger.

```
node verifier/bb-verify.js ~/.blackbox/ledger.jsonl
node verifier/bb-verify.js ledger.jsonl --key signer.pub.pem --anchor anchors.jsonl
node verifier/bb-verify.js ledger.jsonl --blobs ~/.blackbox/blobs --keys ~/.blackbox/keys
```

| option | meaning |
|--------|---------|
| `--key FILE` | the signer's public key (SPKI PEM), obtained out of band. Without it the chain is only checked against the key in its own genesis record. |
| `--anchor FILE` | one or more published chain heads (`anchors.jsonl`). Each must match the ledger. This is what catches a truncated or fully re-signed ledger. |
| `--blobs DIR` | also check payload blobs (conformance level 2). |
| `--keys DIR`, `--master-key HEX` | key material to open sealed blobs (`master.key` and `sessions/`). Without them sealed blobs are not opened. |
| `--json` | machine-readable result: `ok`, `level`, `records`, `head`, `errors`, `warnings`, `erased_keys`. |

Exit code 0: passed. 1: failed. 2: bad usage.

It also works as a module: `const { verifyLedger } = require('./bb-verify')`.

It is tested against every case in [`docs/spec/vectors/`](../docs/spec/vectors/)
and against ledgers written by the recorder (`test/spec-verifier.test.js`).
