# Architecture

## Data flow

```
agent (Claude Code, Codex, Cursor, Gemini)
  │  hook event (JSON)
  ▼
bin/hook.js ──(adapter decode)──► daemon  /hook
                                    │ 1. policy sees the RAW event (learns secrets, taint, docs)
                                    │ 2. a scrubbed copy is encrypted (vault) and appended (ledger)
                                    │ 3. decision: allow | ask | deny
  ◄── verdict (adapter encode) ─────┘
```

The daemon is a separate process and holds the signing key. If it is down, `bin/hook.js` spools the event and replays it later (or fails closed, by config). The UI, the CLI and the read-only agent API all read the same ledger.

## Module map

| Area | Files | Role |
|---|---|---|
| Recording | `src/daemon.js`, `src/ledger.js`, `src/vault.js`, `src/merkle.js`, `src/anchor.js` | the daemon, the hash-chained Ed25519 ledger, per-session AES-GCM payloads with crypto-erase, Merkle batches and opt-in anchoring |
| Policy | `src/policy.js` | the lethal-trifecta rules, egress detection, memory-document provenance, scrubbing |
| Hooks | `bin/hook.js`, `src/adapters/*.js`, `src/integrity.js` | the command the agent runs, one adapter per agent, the check that the hooks are still installed |
| Install | `src/install.js`, `src/install-agent.js`, `src/install-cli.js`, `src/harden.js` | wiring into agent settings; `harden` runs the recorder as a dedicated OS user |
| CLI | `bin/blackbox.js`, `src/term.js`, `src/paths.js`, `src/local-http.js` | commands, colors, locations and config, the minimal client |
| Audits | `src/scan.js`, `src/scan-worker.js`, `src/scan-html.js`, `src/share.js`, `src/mcp.js`, `src/skills.js`, `src/*-report.js` | retroactive scan of transcripts, MCP and skill audits and their reports |
| Agent surface | `src/agent-api.js`, `src/mcp-server.js`, `src/otel-genai.js` | read-only JSON API, a local MCP server, OpenTelemetry export |
| Shared | `src/util.js`, `src/types.d.ts` | small helpers and shared types |
| Verification | `verifier/`, `docs/spec/` | a standalone verifier and the open ledger format |
| Quality | `test/`, `eval/`, `bench/` | unit and integration tests, the attack corpus, latency budgets |

## Build

`scripts/build.js` compiles `src/`, `bin/` and `eval/` (`.js` and `.ts`) into the committed `dist/` with `tsconfig.build.json`. CI runs `build:check` to reject a stale `dist/`.

## Types

`tsconfig.json` checks everything leniently. `tsconfig.strict.json` adds `noImplicitAny` over an explicit file list; a new file joins it from the start.

## Hardened mode

With `blackbox harden` the daemon runs as its own OS user from a root-owned copy of the code. The agent, running as the human, holds only an ingest token: it can write evidence but not read, rewrite or erase it. The admin token is read through `sudo`. See `src/harden.js` and [PRIVACY.md](PRIVACY.md).
