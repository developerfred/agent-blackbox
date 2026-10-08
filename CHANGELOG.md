# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic versioning](https://semver.org/) once 1.0 ships (until then a minor version may change behavior, and each entry says so).

To cut a release: move the entries under "Unreleased" to a new version heading, bump `version` in `package.json` and `.claude-plugin/plugin.json`, merge, then push the tag `vX.Y.Z`. The `release` workflow checks that the tag matches `package.json`, runs the checks and publishes.

## Unreleased

Everything below landed after v0.2.0.

### Added
- Agent API: read-only, versioned `/v1/agent/*` endpoints (capabilities, OpenAPI, rules, status, sessions, records) and `blackbox serve-mcp`, a local stdio MCP server over the same API. `--json` for `status`, `sessions`, `timeline`, `verify` and `docs`.
- `blackbox brief`: a Markdown summary of one session.
- `blackbox export`: the ledger as OpenTelemetry GenAI traces and logs, local by default.
- Merkle batching of the ledger (`blackbox anchor --batch`), inclusion proofs, and opt-in automatic anchoring of the chain head to a file or webhook (`anchor --auto`).
- Open ledger format v1 ([docs/spec/ledger-v1.md](docs/spec/ledger-v1.md)), test vectors, and the standalone verifier `bb-verify` (now also published in the npm package).
- Adapters for Codex CLI, Cursor and Gemini CLI, and `blackbox eval --agent all`. Not yet tried against the real agents.
- Memory provenance: a document written by a session that had read untrusted content taints a later session that loads it; `blackbox docs` lists and clears the marks.
- Memory guard: a tainted session cannot plant text in `AGENTS.md`, `CLAUDE.md` and other files later sessions trust.
- `blackbox harden`: the recorder as its own OS user, hooks in root-owned code, `--check` for leftovers, hook self-report in hardened mode.
- Privacy pass: encrypted summaries, prompt text only with `install --prompts`, `retainDays`, and [docs/PRIVACY.md](docs/PRIVACY.md).
- `scan` replays transcripts on worker threads (`--jobs N`), about 3x faster on 4 cores for large histories.
- Crypto and Web3 rules: seed phrases, private keys, wallet files, signing and broadcasting transactions.
- Evasion corpus grew to 99 cases: 71 attacks (all caught) and 28 benign (no false alarms).

### Changed
- The code is TypeScript, compiled to a committed `dist/` that the plugin hooks, the npm `bin` and the Homebrew formula run, so nothing needs a build at install time. Runtime dependencies are still zero.
- The daemon keeps record offsets, not records, in memory and reads timeline records on demand.

### Fixed
- `redact` keeps `[secret:<fingerprint>]` markers; `status` and the CLI use the right token and data folder when the recorder runs as its own user; `harden` stops on a node the recorder user cannot run and points the service at the stable Homebrew node.
