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
- [x] Privacy pass: summaries encrypted per session and erased by `purge`, prompt text via telemetry opt-in (`install --prompts`), install prints key and fail-open posture (`--fail-closed`), `retainDays`, [docs/PRIVACY.md](docs/PRIVACY.md)
- [ ] Master key still readable by the same user unless the recorder runs under `blackbox harden`; make the safe posture easier to reach
- [x] Close the known gaps: repository files as untrusted input, data in allowlisted URLs, pre-existing scripts

**Gate:** 3 outside developers use it for a week with fewer than 1 false alarm per day.

## Phase 1: open-source adoption (weeks 3–6)

- [ ] Launch: demo GIF, Show HN, X, Farcaster, r/ClaudeAI on the same day
- [ ] Prompt-injection challenge repo with a canary token
- [x] Open ledger and event format: versioned spec, test vectors and a standalone verifier ([docs/spec/ledger-v1.md](docs/spec/ledger-v1.md), [verifier/](verifier/README.md)). `blackbox verify` enforces the same rules. Still open: ship `bb-verify` in the npm package, key rotation
- [x] `blackbox export`: ledger as OpenTelemetry GenAI traces and logs, local by default ([docs/OTEL.md](docs/OTEL.md))
- [ ] Adapters for Codex CLI, Cursor and Gemini CLI (one canonical event, OpenTelemetry GenAI conventions): adapter interface, Codex and Cursor merged, Gemini CLI in review; see [docs/AGENTS.md](docs/AGENTS.md) for what each adapter does not cover yet
- [ ] Inspect and pin MCP tool definitions (descriptions, not just configs); alert on changes and hidden instructions ([MCPTox](https://arxiv.org/abs/2508.14925)). Today `blackbox mcp --pin` pins how a server is configured (command, arguments, URL), not the text of its tool descriptions
- [x] Merkle batching of the chain: `blackbox anchor --batch`, inclusion proofs ([docs/ANCHORING.md](docs/ANCHORING.md))
- [x] Automatic anchoring of the chain head, opt-in, to a file or webhook the user names (`blackbox anchor --auto`)
- [x] Agent API: read-only, versioned `/v1/agent/*` endpoints with capabilities, OpenAPI, rules, status, sessions and records, so an agent can read what was recorded without scraping the CLI, plus `blackbox serve-mcp`, a local stdio MCP server over the same API ([docs/AGENT-API.md](docs/AGENT-API.md))
- [x] Agent-readable docs: [docs/AGENT-GUIDE.md](docs/AGENT-GUIDE.md), `llms.txt` and `llms-full.txt` on the site
- [x] Project site on GitHub Pages (English and Portuguese, terminal demos, SEO and social cards, sitemap)
- [ ] Anchoring to a public timestamp authority (RFC 3161, OpenTimestamps) ([Agent Flight Recorder](https://arxiv.org/html/2609.01931))
- [ ] Declarative rules file (trigger, predicate, action) ([AgentSpec](https://arxiv.org/abs/2503.18666))
- [ ] Public evaluation of the policy: attacks that get through and false alarms, measured against defense-aware attacks before any claim ([The Attacker Moves Second](https://arxiv.org/abs/2510.09023))

### Next: the ledger as something other agents and tools can rely on

Today the ledger proves what one session did on one machine. These steps make it checkable by third parties and usable by agents that act for people. Each is a small, separate piece.

- [ ] Spec v1.1: key rotation and revocation, a formal `agent` field, an explicit algorithm field so it can change later. Package `bb-verify` in npm
- [ ] Conformance suite from the existing test vectors, and a second verifier in another language (a format is a standard only with more than one implementation)
- [ ] Agent identity: a key per agent or session, certified by the machine key, with a field that maps to `gen_ai.agent.id`
- [ ] `receipt` record (draft spec first, no code): user intent, policy decision, human approval, payment or transaction hash and effect, with a Merkle inclusion proof a third party can check without seeing the payload. Check x402 and ERC-8004 against their current specifications before mapping to them
- [ ] A trusted anchor target for automatic anchoring (a transparency log or a signed git commit) and third-party verification of its timestamp
- [ ] Test the Codex, Cursor and Gemini adapters against the real agents (their payload shapes come from public write-ups and type definitions) before announcing support

**Gate:** 500 stars and 50 active installs.

## Phase 2: team server (months 2–3)

Privacy rules the team server must meet before any code is written. The promise on the README ("no account, no cloud, no telemetry") stays true for the single-developer tool; team mode is a separate, explicit opt-in.

- **Opt-in per machine, visible to the person at the keyboard.** Nothing is sent until the developer's own recorder is enrolled; enrolment and its endpoint are shown by `blackbox status`.
- **Metadata only by default.** What may leave a machine: session ids, tool names, rule names and decisions, taint flags, secret fingerprints, counts and timestamps. Prompts, tool arguments, tool results, file paths and command text stay on the machine, sealed under keys the server never holds.
- **Evidence stays local, the server holds pointers.** The server stores signed chain heads and record hashes so it can check integrity; a reviewer who needs a payload asks the developer's machine, and the developer approves.
- **Encrypted in transit and at rest, with a retention limit set by the organisation and shown to the developer.**
- **No silent widening.** A policy push can add rules, never switch on more collection; anything that sends more data needs a new opt-in on the machine.
- **Export is the same data.** SIEM export (Splunk, Sentinel, Datadog) carries the same metadata set, nothing more.
- **Deletion works the same way.** Purging a session on the machine also tells the server to drop what it holds about it.


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

- [x] Type-check the current code first: JSDoc types + `tsc --checkJs --noEmit` in CI, zero behavior change (`npm run typecheck`, `strict`; shared types in `src/types.d.ts`). `noImplicitAny` is on for 18 modules (`tsconfig.strict.json`); left: the daemon and the CLI entry point
- [x] Build step for the TypeScript move: `npm run build` compiles `src/`, `bin/` and `eval/` (`.js` and `.ts`) into a committed `dist/`, which the plugin hooks, the Homebrew formula and the npm `bin` run, so nothing needs a build at install time. CI fails when `dist/` is stale (`npm run build:check`). Migrating a module is `git mv x.js x.ts`, fix its types, rebuild.
- [ ] Move to TypeScript module by module (policy, ledger, vault first), compiled to plain JS for npm and the plugin, so users still need only Node
- [ ] Shared types for the canonical event (hooks, Cursor, Codex, OpenTelemetry GenAI) and for the rules file
- [x] Benchmarks in CI: hook round trip under 20 ms at p95, policy decision under 1 ms, `scan` throughput in sessions per second (`npm run bench`; the CI job prints the numbers and does not fail on them, shared runners are too noisy)
- [x] Daemon: payload lookup by record number without a full scan (byte-offset index; p95 25 ms to 1.3 ms in an 8k-record ledger). Still open: incremental index at startup instead of reading the whole ledger
- [x] Hook client: a minimal HTTP client over `net` instead of `http` (about 10 ms less per hook process). A persistent socket does not help here: every hook is a new process
- [x] `scan`: process transcripts in parallel on worker threads (`--jobs N`, `--jobs 1` for single-threaded)
- [ ] Optional single binary (Node SEA or Bun) for the Homebrew formula

TypeScript makes the code safer to change and easier for contributors; the speed comes from the items above, which are measured.

## Not on the roadmap

- Our own prompt-injection detection model: others already do this, and detection alone is what adaptive attacks break.
- Generic LLM observability (prompts, latency, cost dashboards): Langfuse, Phoenix and others do it well; we export to them.
