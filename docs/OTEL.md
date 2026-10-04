# OpenTelemetry GenAI export

`blackbox export` turns the ledger into OTLP/JSON that follows the [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) where one exists, so the record of what an agent did can be read by any OTel tool.

**Local by default.** With no flags it writes `traces.json` and `logs.json` to a folder and sends nothing. It sends data only to the URL you pass with `--endpoint`, and never anywhere else.

```
blackbox export [--session ID] [--out dir] [--endpoint URL]
```

**Metadata only.** Session, tool and rule names, decisions, timestamps and chain hashes. Never prompts, commands, paths, tool arguments, results or summaries; those stay in the ledger, sealed under the session key.

## Mapping

| Ledger | OTel |
|---|---|
| `PreToolUse` .. `PostToolUse` / `PostToolUseFailure` (same `tool_use_id`) | span `execute_tool <tool>` |
| `session_id` | `gen_ai.conversation.id`, and the trace id (sha256 of it) |
| `tool_name`, `tool_use_id`, `agent_id` | `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.agent.id` |
| (constant) | `gen_ai.operation.name=execute_tool`, `gen_ai.provider.name=anthropic` |
| `decision` records | span event and log record `blackbox.decision`; a deny or ask sets the span status to error |
| `taint`, `intent`, `purge`, `settings`, `genesis` | log records `blackbox.<kind>` |

Attributes the conventions do not define use the `blackbox.*` namespace: `blackbox.decision`, `blackbox.rule`, `blackbox.taint`, `blackbox.record.seq`, `blackbox.record.hash` (the ledger position, so an exported span can be checked against `blackbox verify`).

Trace and span ids are derived from session and tool-call ids, so exporting the same ledger twice gives the same ids.

The GenAI conventions are still in development; the attribute names live in one table (`GENAI` in `src/otel-genai.js`) so they can follow upstream.

Not covered yet: model-call spans (`chat`, with model and token usage). They need the telemetry payloads, which are sealed, so they will come as an explicit opt-in.
