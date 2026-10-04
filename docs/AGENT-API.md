# Agent API

A read-only, versioned JSON API for AI agents (or an MCP server acting for one) to learn what agent-blackbox is and to read back what it recorded, without scraping the CLI or the UI. It is served by the recorder on `127.0.0.1` (default port 7071, `BLACKBOX_PORT` overrides it) under `/v1/agent/`.

Start with `GET /v1/agent/capabilities`: it lists every endpoint, the rule names, the record kinds and what the API never returns. `GET /v1/agent/openapi.json` describes the same API as OpenAPI 3.1, generated from the same table, so the two cannot drift apart.

## Authentication and scopes

Send the token in the `x-blackbox-token` header, like every other recorder endpoint. Two tiers, using the two tokens that already exist:

| Tier | Token | Endpoints |
| --- | --- | --- |
| public | ingest token (the one hooks hold) or admin token | `capabilities`, `openapi.json`, `status`, `rules` |
| admin | admin token | `sessions`, `records` |

The public tier is what the agent itself may read, so it says nothing about enforcement: no mode, no findings, no reasons for a denial (see "Denials stay quiet" in the README). Records and sessions are for the human, or for an agent the human delegates the admin token to.

With the recorder as a dedicated user (`blackbox harden`) the admin token is not readable by the agent's OS user; with the default same-user install every token is readable by any process running as you, as described in [PRIVACY.md](PRIVACY.md).

## Endpoints

All responses are JSON with a `schema` field (`blackbox.agent/v1`). New optional fields may appear; existing fields keep their meaning within `v1`.

| Endpoint | Scope | Returns |
| --- | --- | --- |
| `GET /v1/agent/capabilities` | public | name, version, endpoints, rule ids, record kinds, guarantees |
| `GET /v1/agent/openapi.json` | public | OpenAPI 3.1 document |
| `GET /v1/agent/status` | public | `recording`, `ledger_seq`, `chain_ok`, `encrypted` |
| `GET /v1/agent/rules` | public | rule catalogue: `id`, usual `decision`, one-line `summary` |
| `GET /v1/agent/sessions` | admin | sessions, newest first: id, first/last time, cwd, event/tool/decision counts, taint flag names |
| `GET /v1/agent/records` | admin | compact records; query `session`, `kind` (default `decision,taint`), `after` (cursor), `limit` (1 to 500, default 100); `next_after` is the cursor for the next page or `null` |

## What is never returned

- Payloads (prompts, tool arguments, tool results) and hook summaries. Only record metadata, rule names and the already-masked `reason` and `why` text that the ledger stores in clear (see [PRIVACY.md](PRIVACY.md)).
- Signatures, keys and tokens.
- Anything from another machine: the recorder rejects requests that are not addressed to loopback.

Record fields follow [spec/ledger-v1.md](spec/ledger-v1.md); `records` returns the subset `seq`, `ts`, `kind`, `hash`, `event`, `session_id`, `prompt_id`, `tool_name`, `tool_use_id`, `decision`, `rule`, `reason`, `flag`, `why`, `hosts`, and the settings/anchor fields.

## Example

```sh
TOKEN=$(cat ~/.blackbox/keys/token)
curl -s -H "x-blackbox-token: $TOKEN" http://127.0.0.1:7071/v1/agent/capabilities
curl -s -H "x-blackbox-token: $(cat ~/.blackbox/keys/admin-token)" \
  "http://127.0.0.1:7071/v1/agent/records?kind=decision&limit=20"
```
