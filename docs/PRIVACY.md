# Privacy

What agent-blackbox records, where it keeps it, how long, and what leaves your machine.

## What leaves your machine

Nothing. The code opens no outbound connection: the recorder listens on `127.0.0.1` only (`src/daemon.js`), the hook and CLI talk to it over loopback (`src/local-http.js`), and the local UI loads no external script, font or image. There are no runtime dependencies. `blackbox share` and `scan --card` draw images from aggregate numbers and fixed category labels, never from project names, hosts, commands or prompts.

The one exception is something you do on purpose: a file you publish yourself (a share card, an `anchor` head).

## What is recorded, and where

Everything lives in `~/.blackbox/` (folders `0700`, files `0600`).

| What | Where | Protection |
| --- | --- | --- |
| Record metadata: sequence, time, event kind, tool name, session id, working directory of a session start, decisions and rule names | `ledger.jsonl` | clear text, hash-chained and signed |
| One-line summary of each hook record (prompt, command, path text, secrets masked) | `ledger.jsonl` | sealed with the session key (AES-256-GCM) |
| Full payloads: prompt, tool arguments, tool results | `blobs/<key>/` | sealed with the session key, secrets replaced by fingerprints |
| Prompt and response text through telemetry | blobs | only with `install --prompts` |
| Full model request and response bodies | blobs | only with `install --raw`; Claude Code writes them in clear text to `api-bodies/` until the recorder scrubs and moves them (about 3 minutes at most) |
| Secrets | never stored | replaced by `[secret:<fingerprint>]`; the fingerprint is a truncated HMAC with a per-install salt |

Session keys are wrapped by a master key. `blackbox purge` or `retainDays` destroys a session key: that session's payloads and summaries become unreadable everywhere, backups included. The chain keeps every hash and still verifies.

Still in clear text after a purge: record metadata, the working directory of session starts, rule names and the reasons of decisions (secrets masked). These are what lets `verify` and the timeline keep working.

## Retention

Nothing is deleted unless you ask. `blackbox purge --days N` erases on demand; `"retainDays": N` in `~/.blackbox/config.json` does it automatically (at start, then hourly). Off by default.

## What the defaults do not protect against

- A process running as your user can read the master key and the signing key. `blackbox harden` runs the recorder as a dedicated user and closes this; `blackbox install` tells you which case you are in.
- Fingerprints of low-entropy secrets (a short password) can be brute-forced by someone who has the per-install salt, which sits in `state.json` next to the keys. Long random secrets (API keys, tokens) are not at risk.
- Hosts in `allowHosts` (github.com, npm, PyPI, crates.io, Anthropic) do not count as outbound for the lethal-trifecta rule. Publishing commands still do.
- By default the recorder fails open: if it is down, tools still run. `blackbox install --fail-closed` denies instead.

## Team mode

Not built. The privacy rules it must meet before any code are in [ROADMAP.md](../ROADMAP.md).
