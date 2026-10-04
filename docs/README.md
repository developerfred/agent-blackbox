# Documentation

- [PRIVACY.md](PRIVACY.md): what is recorded, where it is kept, retention, and what the defaults do not protect against
- [spec/ledger-v1.md](spec/ledger-v1.md): the open ledger and event format (hash chain, signatures, sealed payloads, crypto-erase)
- [ANCHORING.md](ANCHORING.md): Merkle batches of the chain, inclusion proofs, publishing the head
- [OTEL.md](OTEL.md): `blackbox export`, the ledger as OpenTelemetry GenAI traces and logs (local by default)
- [../verifier/](../verifier/README.md): `bb-verify.js`, a standalone verifier for that format (no dependencies)
- [../README.md](../README.md): install, policy rules, evidence format, limitations
- [../SECURITY.md](../SECURITY.md): reporting a vulnerability or a policy bypass
- [../ROADMAP.md](../ROADMAP.md): phases, gates and the engineering track

The project site is built from `site/` and published with GitHub Pages.
