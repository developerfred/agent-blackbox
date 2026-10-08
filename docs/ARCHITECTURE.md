# Architecture

## Data flow

```
agent (Claude Code, Codex, Cursor, Gemini)
  │  hook event (JSON)
  ▼
bin/hook.ts ──(adapter decode)──► daemon  /hook
                                    │ 1. policy sees the RAW event (learns secrets, taint, docs)
                                    │ 2. a scrubbed copy is encrypted (vault) and appended (ledger)
                                    │ 3. decision: allow | ask | deny
  ◄── verdict (adapter encode) ─────┘
```

The daemon is a separate process and holds the signing key. If it is down, `bin/hook.ts` spools the event and replays it later (or fails closed, by config). The UI, the CLI and the read-only agent API all read the same ledger.

## Module map

| Area | Files | Role |
|---|---|---|
| Recording | `src/daemon.ts`, `src/ledger.ts`, `src/vault.ts`, `src/merkle.ts`, `src/anchor.ts` | the daemon, the hash-chained Ed25519 ledger, per-session AES-GCM payloads with crypto-erase, Merkle batches and opt-in anchoring |
| Policy | `src/policy.ts` | the lethal-trifecta rules, egress detection, memory-document provenance, scrubbing |
| Hooks | `bin/hook.ts`, `src/adapters/*.ts`, `src/integrity.ts` | the command the agent runs, one adapter per agent, the check that the hooks are still installed |
| Install | `src/install.ts`, `src/install-agent.ts`, `src/install-cli.ts`, `src/harden.ts` | wiring into agent settings; `harden` runs the recorder as a dedicated OS user |
| CLI | `bin/blackbox.ts`, `src/term.ts`, `src/paths.ts`, `src/local-http.ts` | commands, colors, locations and config, the minimal client |
| Audits | `src/scan.ts`, `src/scan-worker.ts`, `src/scan-html.ts`, `src/share.ts`, `src/mcp.ts`, `src/skills.ts`, `src/*-report.ts` | retroactive scan of transcripts, MCP and skill audits and their reports |
| Agent surface | `src/agent-api.ts`, `src/mcp-server.ts`, `src/otel-genai.ts` | read-only JSON API, a local MCP server, OpenTelemetry export |
| Shared | `src/util.ts`, `src/types.d.ts` | small helpers and shared types |
| Verification | `verifier/`, `docs/spec/` | a standalone verifier and the open ledger format |
| Quality | `test/`, `eval/`, `bench/` | unit and integration tests, the attack corpus, latency budgets |

## Build

`scripts/build.js` compiles `src/`, `bin/` and `eval/` into the committed `dist/` with `tsconfig.build.json`. CI runs `build:check` to reject a stale `dist/`.

## Types

`tsconfig.json` checks everything leniently. `tsconfig.strict.json` adds `noImplicitAny` over an explicit file list; a new file joins it from the start.

## Hardened mode

With `blackbox harden` the daemon runs as its own OS user from a root-owned copy of the code. The agent, running as the human, holds only an ingest token: it can write evidence but not read, rewrite or erase it. The admin token is read through `sudo`. See `src/harden.ts` and [PRIVACY.md](PRIVACY.md).
