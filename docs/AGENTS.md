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
| Gemini CLI | `blackbox install --agent gemini` | yes, for every tool | no: an ask becomes a block | yes | see below |
| Cursor | `blackbox install --agent cursor` | yes, for shell and MCP calls | yes | shell, MCP and file reads (with content) | file edits are recorded after the fact; see below |

### Codex CLI

Hooks live in `~/.codex/hooks.json` (or `$CODEX_HOME`). The adapter registers `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` and `Stop`. Codex's payloads follow Claude Code's, so the adapter only renames what differs: an `apply_patch` call becomes an `Edit` of every file in the patch (so the memory-write and hook-tamper rules see all of them), and `web_search` becomes `WebSearch`.

Limits to know before relying on it:

- **`PreToolUse` does not see every tool.** It covers Bash, `apply_patch` and MCP calls. Codex's other built-ins, such as web search, are not gated, and what they return is not seen by the policy.
- **Codex cannot ask you.** Where Claude Code would show a permission prompt, Codex gets a block (the model sees only the uninformative message, you see the reason). Set `"askFallback": "allow"` in `~/.blackbox/config.json` to let those calls run with a notice instead.
- **Hooks are experimental in Codex and may need enabling** in `~/.codex/config.toml`; the installer says so. The `PermissionRequest` event is not used.
- The payload shapes above were taken from third-party write-ups of the Codex hooks, not from OpenAI's own documentation (not reachable when this was written). Check them against your Codex version; a payload the adapter cannot read is skipped, never a reason to stop the agent.

### Cursor

Hooks live in `~/.cursor/hooks.json`, one command per event name. The adapter registers `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt` and `stop`, and maps them to the canonical events (`beforeShellExecution` is a `PreToolUse` of `Bash`, an MCP call is `mcp__<server>__<tool>`, and so on). Cursor names the MCP tool but not always the server, so the server is taken from the payload's server name, else the URL's host, else the command's name.

Limits to know before relying on it:

- **File edits are not gated.** Cursor's edit hook runs after the edit (`afterFileEdit`), so the memory-write rule and the hook-tamper rule on an edit are seen and recorded, but cannot stop the write. Shell commands, including `sed -i` and redirects, are gated as usual.
- **File reads are never blocked.** The read hook carries the file's content, so the session learns what it read (private data, injected text), and the trifecta rule fires later on the egress.
- **Other Cursor hook points are not used.** Newer events (a generic tool hook, session start and end, subagents) are not registered until they have been checked against a real Cursor.
- The reply fields are written in both `snake_case` and `camelCase` (`user_message` and `userMessage`), because the documentation and the type definitions I could reach disagree. As with Codex, the payload shapes come from third-party examples; the official page was not reachable. Restart Cursor after installing.

### Gemini CLI

Hooks live in `~/.gemini/settings.json` under `hooks`. The adapter registers `SessionStart`, `SessionEnd`, `BeforeAgent` (the prompt), `AfterAgent`, `BeforeTool`, `AfterTool` and `Notification`, and renames the tools: `run_shell_command` is `Bash`, `read_file` and `read_many_files` are `Read`, `write_file` is `Write`, `replace` is `Edit`, `web_fetch` is `WebFetch`, `google_web_search` is `WebSearch`, and MCP tools (named by their `mcp_context`) are `mcp__<server>__<tool>`. `save_memory`, which appends to the `GEMINI.md` later sessions load as instructions, is seen as a write to that file, so the memory-write rule covers it. Gemini's `web_fetch` takes a prompt that holds the URLs; every URL in it is checked.

Limits to know before relying on it:

- **Gemini cannot ask you.** An `ask` becomes a block (`"askFallback": "allow"` lets it run with a notice). Denials use `decision: "deny"`; the model sees only the uninformative reason and you see the detail.
- **Hooks may need enabling** in your Gemini settings, and apply to new sessions.
- Gemini's model-level hooks (`BeforeModel`, `AfterModel`, `BeforeToolSelection`) are not used; the recorder sees tool calls, prompts and turns, not model traffic, and there is no OpenTelemetry stream like Claude Code's.
- The event names, tool names and reply shape follow Gemini CLI's hooks reference in its repository. The tool parameter names (`file_path`, `prompt`, `paths`) are from memory of Gemini's tools and have not been run against a real Gemini; check them with your version.

## Measuring an adapter

`blackbox eval --agent codex|cursor|gemini|all` runs the evasion corpus through an adapter. Every corpus event is re-written the way that agent would send it (a Codex session reads files with `cat` and fetches pages with `curl`, since it has no tools for them), decoded by the real adapter, and then judged by the policy. For each agent it prints the attacks caught, the false alarms, the cases that give a different answer than in Claude Code's own format (a loss in translation, which fails the run), and the cases the agent has no hook for.

Today every adapter catches what Claude Code catches on the cases it can express, with no extra false alarms. The cases an agent cannot express are the limits listed above made visible: all three lack PowerShell, and Cursor cannot gate the memory-write and planted-document cases because its edit hook runs after the write.

This measures the mapping, not the agent. The re-writing is ours, built from the same reading of each agent's hooks as the adapter; it shows nothing is lost on the way in, and does not show that a real Codex, Cursor or Gemini sends these payloads. That still needs a run on the real agent.

## Adding an agent

1. `src/adapters/<id>.js` exporting an `Adapter` (see `src/types.d.ts`), and its id in `src/adapters/index.js`.
2. Map the agent's events and tool names onto the canonical ones. Keep fields the policy reads (`command`, `file_path`, `url`, `tool_response`) under Claude Code's names.
3. State only the capabilities you verified against the agent's own documentation, and say where it cannot block.
4. Test it with `test/adapter-harness.js`, which runs the real hook script against a real recorder, and add an encoder for it to `eval/native.js` so `blackbox eval --agent <id>` can measure it.
