# Agents and adapters

agent-blackbox records and gates one canonical event stream. Claude Code's hook events (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, ...) with Claude Code's tool names (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, `mcp__server__tool`) are that format. The policy, the vault and the ledger know nothing else.

An **adapter** (`src/adapters/<agent>.js`) is the only code that knows one agent's own hook format. It does three things:

| Method | Does |
|---|---|
| `decode(native)` | turns the agent's hook payload into a canonical event, naming tools the way the policy expects (`run_shell_command` becomes `Bash`). Returns `null` for events nothing is recorded for. |
| `encode(reply, native, opts)` | turns the recorder's neutral verdict (`permission: 'ask' \| 'deny' \| null`, the human's reason, the model's uninformative message, a notice) into what the agent reads on stdout and by exit code. |
| `failClosed(event, reason, native)` | what to print when the recorder is down and `failMode` is `closed`. |

`capabilities` states, per agent, what its hooks can do. It is documentation the code can check, not a promise made on the agent's behalf:

- `preTool`: a hook can stop a tool call before it runs. Without it the agent is **recorded but not enforced**.
- `ask`: a hook can hand the decision to the human. Without it, an `ask` verdict becomes a block (or is let through with a notice, when `askFallback` is `allow` in `~/.blackbox/config.json`).
- `postTool`: tool results reach a hook. Without it the policy cannot learn what a session has read, so the trifecta rules cannot fire.
- `prompt`, `session`: prompts and session start/end are recorded.

Events recorded for an agent other than Claude Code carry `agent` (`codex`, `cursor`, `gemini`); Claude Code's carry none, as before.

The hook script picks its adapter with `--agent <id>` (default `claude`). Adapters load lazily and use no dependencies.

## What each agent can enforce

| Agent | Install | Block before a tool runs | Ask the human | Sees tool results | Notes |
|---|---|---|---|---|---|
| Claude Code | `blackbox install` (or the plugin) | yes | yes | yes | 14 lifecycle events, OpenTelemetry too |
| OpenAI Codex CLI | `blackbox install --agent codex` | yes, for Bash, `apply_patch` and MCP calls | no: an ask becomes a block | yes | see below |

### Codex CLI

Hooks live in `~/.codex/hooks.json` (or `$CODEX_HOME`). The adapter registers `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` and `Stop`. Codex's payloads follow Claude Code's, so the adapter only renames what differs: an `apply_patch` call becomes an `Edit` of every file in the patch (so the memory-write and hook-tamper rules see all of them), and `web_search` becomes `WebSearch`.

Limits to know before relying on it:

- **`PreToolUse` does not see every tool.** It covers Bash, `apply_patch` and MCP calls. Codex's other built-ins, such as web search, are not gated, and what they return is not seen by the policy.
- **Codex cannot ask you.** Where Claude Code would show a permission prompt, Codex gets a block (the model sees only the uninformative message, you see the reason). Set `"askFallback": "allow"` in `~/.blackbox/config.json` to let those calls run with a notice instead.
- **Hooks are experimental in Codex and may need enabling** in `~/.codex/config.toml`; the installer says so. The `PermissionRequest` event is not used.
- The payload shapes above were taken from third-party write-ups of the Codex hooks, not from OpenAI's own documentation (not reachable when this was written). Check them against your Codex version; a payload the adapter cannot read is skipped, never a reason to stop the agent.

## Adding an agent

1. `src/adapters/<id>.js` exporting an `Adapter` (see `src/types.d.ts`), and its id in `src/adapters/index.js`.
2. Map the agent's events and tool names onto the canonical ones. Keep fields the policy reads (`command`, `file_path`, `url`, `tool_response`) under Claude Code's names.
3. State only the capabilities you verified against the agent's own documentation, and say where it cannot block.
4. Test it with `test/adapter-harness.js`, which runs the real hook script against a real recorder.
