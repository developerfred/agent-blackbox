# Roadmap

agent-blackbox starts as a free tool a developer installs on their own machine and grows into what a security team deploys to every machine: evidence and control over what AI coding agents do, across agent vendors, with proof a third party can verify.

Each phase ends with a gate. We move on when the gate is met, not when the date arrives. Targets are goals to calibrate, not forecasts.

## Phase 0: solid base (now)

- [x] Hash-chained, signed ledger; hooks, native telemetry, raw model bodies
- [x] Lethal-trifecta policy; secrets scrubbed before writing; token on every endpoint; purge
- [x] Quiet denials and post-denial asking ([Causality Laundering](https://arxiv.org/abs/2604.04035))
- [x] User intent from the prompt ([Progent](https://arxiv.org/abs/2504.11703))
- [x] Credential-printing commands count as private data ([arXiv:2604.03070](https://arxiv.org/abs/2604.03070))
- [x] `blackbox scan` of past sessions with a shareable card
- [x] Homebrew formula and npm package metadata
- [x] Local HTML report: tool categories, per-project composition, shell programs, network destinations
- [x] `blackbox skills`: audit installed skills across agents, pin them, gate risky ones live
- [x] `blackbox mcp`: MCP servers used and their tools, config audit across clients, pin, live gate
- [x] `blackbox share`: X card, story image and video from local numbers only
- [x] Encrypt payloads at rest, with per-session keys for real crypto-erasure (`purge --session`, `show`)
- [x] Claude Code plugin packaging (hooks bundled in a plugin, marketplace in this repo)
- [x] Running code counts as possible egress; publishing commands; obfuscation-resistant matching (external review)
- [x] Evasion corpus as regression tests and `blackbox eval` (62/62 caught, 0/20 false alarms, 0 known gaps open)
- [x] Hook integrity checks in the daemon; `blackbox managed-settings` for admin-owned hooks
- [x] Token scopes: the hooks' token can add events but not read or erase them
- [x] Run the recorder as a dedicated OS user (`blackbox harden`: launchd / systemd), so the agent can write evidence but not read or erase it
- [x] Crypto and Web3: seed phrases, private keys, wallet files, signing and broadcasting transactions
- [x] Close the known gaps: repository files as untrusted input, data in allowlisted URLs, pre-existing scripts

**Gate:** 3 outside developers use it for a week with fewer than 1 false alarm per day.

## Phase 1: open-source adoption (weeks 3–6)

- [ ] Launch: demo GIF, Show HN, X, Farcaster, r/ClaudeAI on the same day
- [ ] Prompt-injection challenge repo with a canary token
- [ ] Adapters for Codex CLI and Cursor (one canonical event, OpenTelemetry GenAI conventions)
- [ ] Inspect and pin MCP tool definitions (descriptions, not just configs); alert on changes and hidden instructions ([MCPTox](https://arxiv.org/abs/2508.14925))
- [ ] Merkle batching and automatic anchoring of the chain head ([Agent Flight Recorder](https://arxiv.org/html/2609.01931))
- [ ] Declarative rules file (trigger, predicate, action) ([AgentSpec](https://arxiv.org/abs/2503.18666))
- [ ] Public evaluation of the policy: attacks that get through and false alarms, measured against defense-aware attacks before any claim ([The Attacker Moves Second](https://arxiv.org/abs/2510.09023))

**Gate:** 500 stars and 50 active installs.

## Phase 2: team server (months 2–3)

- [ ] Fleet view: agents, MCP servers and plugins on every machine; flagged sessions
- [ ] Central policy pushed through MDM and each agent's managed settings
- [ ] SSO, Slack alerts, SIEM export (Splunk, Sentinel, Datadog)
- [ ] Learn rule revisions from the human's answers to prompts ([AutoSpec](https://arxiv.org/abs/2606.24245))

**Gate:** 3 companies in a pilot and 1 letter of intent.

## Phase 3: compliance and sovereignty (months 3–6)

- [ ] Auditor-ready reports mapped to ISO 27001 logging, SOC 2 and EU AI Act record-keeping
- [ ] Retention policies; hardware-backed keys (Secure Enclave, TPM, HSM)
- [ ] On-premise edition for government and banks
- [ ] Offline semantic audit of recorded sessions for transformed data ([Ghost in the Agent](https://arxiv.org/abs/2604.23374))
- [ ] Exfiltration checks on links and images in agent responses ([EchoLeak](https://arxiv.org/abs/2509.10540))

**Gate:** 1 paid pilot.

## Phase 4: research as the moat

- [ ] Community attack corpus and a benchmark for coding agents
- [ ] Contribute audit attributes to the OpenTelemetry GenAI conventions
- [ ] Provenance-graph record format (intent, policy evaluation, approval, execution, effects)

**Gate:** agent-blackbox is the reference people cite for coding-agent security.

## Engineering track: TypeScript and performance

Runs alongside the phases. The rule: no runtime dependencies, and nothing gets slower without a benchmark saying so.

- [x] Type-check the current code first: JSDoc types + `tsc --checkJs --noEmit` in CI, zero behavior change (`npm run typecheck`, `strict`; shared types in `src/types.d.ts`). Next: turn on `noImplicitAny` (about 470 untyped parameters, mostly in skills, scan, policy and daemon)
- [ ] Move to TypeScript module by module (policy, ledger, vault first), compiled to plain JS for npm and the plugin, so users still need only Node
- [ ] Shared types for the canonical event (hooks, Cursor, Codex, OpenTelemetry GenAI) and for the rules file
- [x] Benchmarks in CI: hook round trip under 20 ms at p95, policy decision under 1 ms, `scan` throughput in sessions per second (`npm run bench`; the CI job prints the numbers and does not fail on them, shared runners are too noisy)
- [x] Daemon: payload lookup by record number without a full scan (byte-offset index; p95 25 ms to 1.3 ms in an 8k-record ledger). Still open: incremental index at startup instead of reading the whole ledger
- [x] Hook client: a minimal HTTP client over `net` instead of `http` (about 10 ms less per hook process). A persistent socket does not help here: every hook is a new process
- [ ] `scan`: stream transcripts and process projects in parallel (worker threads)
- [ ] Optional single binary (Node SEA or Bun) for the Homebrew formula

TypeScript makes the code safer to change and easier for contributors; the speed comes from the items above, which are measured.

## Not on the roadmap

- Our own prompt-injection detection model: others already do this, and detection alone is what adaptive attacks break.
- Generic LLM observability (prompts, latency, cost dashboards): Langfuse, Phoenix and others do it well; we export to them.
