# Using agent-blackbox from an AI agent

For coding agents (Claude Code, Codex, Cursor, Gemini CLI) and for agents setting it up for a person. Plain facts, no marketing. The authoritative references are [README.md](../README.md), [docs/PRIVACY.md](PRIVACY.md) and [docs/spec/ledger-v1.md](spec/ledger-v1.md).

## What it is

A local recorder and policy for coding agents. Hooks send every prompt, tool call and result to a recorder on `127.0.0.1`, which writes a hash-chained, Ed25519-signed ledger in `~/.blackbox/`. Before each tool call a deterministic policy decides `allow` (by saying nothing), `ask` or `deny`. Nothing leaves the machine.

## If a tool call of yours is blocked

The message reads "Blocked by the local security policy." Do this:

1. Stop. Do not retry the call, rephrase it, split it, encode it or reach the same result another way. A retry after a denial is itself a signal and raises the bar for later calls.
2. Tell the person what you were trying to do and why, in one or two sentences.
3. Let them decide. They can see the rule and the reason in `blackbox timeline --last`; you cannot, on purpose.

An `ask` is a prompt to the person, not an error. Wait for their answer.

## Do not touch

- `~/.blackbox/` (reading or writing it is denied by the `self-protection` rule).
- Claude Code settings, plugin files and other agents' hook files (`hook-tamper` asks or alerts).
- `blackbox purge`, `blackbox harden`, `blackbox uninstall`, `blackbox mode`: these change evidence or protection. Run them only when the person asked for exactly that.

## Read-only commands that are safe to run

| Command | What you get |
| --- | --- |
| `blackbox status` | whether the recorder is running, its data folder, whether it runs as a dedicated user |
| `blackbox timeline --last` | what the last session did, step by step |
| `blackbox verify` | proof the ledger chain and signatures are intact; names the first broken record |
| `blackbox scan --json` | past Claude Code sessions replayed through the policy, as JSON (`--days N`, `--jobs N`) |
| `blackbox skills --json`, `blackbox mcp --json` | audit of installed skills and MCP servers (`--fail-on high` for CI) |
| `blackbox eval --json` | the policy against the attack corpus |
| `blackbox export --out DIR` | the ledger as OpenTelemetry GenAI traces and logs, metadata only ([docs/OTEL.md](OTEL.md)) |

Prefer `--json` when you will parse the output.

## Reading it programmatically

- `blackbox serve-mcp` is a local stdio MCP server that exposes the recorder as read-only tools. Add `{ "mcpServers": { "blackbox": { "command": "blackbox", "args": ["serve-mcp"] } } }` to the MCP configuration. It is separate from `blackbox mcp`, which audits MCP servers.
- The recorder serves a read-only JSON API on `127.0.0.1` under `/v1/agent/` (start with `GET /v1/agent/capabilities`; `openapi.json` describes the rest). Without the admin token you can read the public tier only: status and the rule catalogue, never why something was denied.
- Most CLI commands take `--json`.

Details and what is never returned: [AGENT-API.md](AGENT-API.md).

## Installing it for a person

```
npm install -g agent-blackbox        # or: brew install developerfred/tap/agent-blackbox
blackbox install                     # hooks + telemetry, starts the recorder
blackbox install --fail-closed       # deny tool calls while the recorder is down
blackbox install --prompts           # also log prompt and response text (off by default)
```

For Claude Code only, the plugin works too: `/plugin marketplace add developerfred/agent-blackbox`, then `/plugin install agent-blackbox@agent-blackbox`. `blackbox install` prints the key location and whether the recorder fails open. To run it as a dedicated OS user so an agent cannot read the keys, `blackbox harden` prints a root script for the person to read and run.

## What the policy does

| Rule | Decision |
| --- | --- |
| `secret-egress`: a secret read earlier appears in an outbound call | deny |
| `sensitive-egress`: one command reads a sensitive file and sends data out | deny |
| `lethal-trifecta`: private data, untrusted content, then an outbound call or opaque code | ask |
| `web3-transaction`: signing or broadcasting a transaction | ask |
| `post-denial`: something was denied, then another call goes out | ask |
| `self-protection`: touching `~/.blackbox` | deny |
| `hook-tamper`: editing agent settings or plugin files | ask or alert |

Hosts the person names in their own prompt count as allowed destinations for that session. Pasted text and turns the agent starts on its own never widen the list.

## Limits you should state accurately

- It reduces risk and keeps evidence; it does not guarantee that no attack gets through.
- The chain proves recorded events were not altered, not that every event was recorded.
- Until `blackbox harden` is run, a process running as the same user can read the keys.
