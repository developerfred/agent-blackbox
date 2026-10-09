# Policy rules

Each rule returns `deny` (blocked, the human sees why) or `ask` (the human decides). The list is also served by the agent API at `/v1/agent/rules`.

| Rule | Decision | What it catches | Why |
|---|---|---|---|
| `secret-egress` | deny | a secret read earlier in the session appears in an outbound call | the value is known to be a secret; there is no innocent reading |
| `sensitive-egress` | deny | one command reads a sensitive file and sends data out | reading and sending in one step is exfiltration |
| `lethal-trifecta` | ask | the session touched private data and untrusted content, and now reaches an unnamed host | the three together are what a prompt injection needs |
| `secret-to-code` | ask | a secret is passed to code the policy cannot inspect | opaque code can send it anywhere |
| `web3-transaction` | ask | signing or broadcasting a transaction, or key material on a command line | irreversible, and a key on a command line is a leak |
| `sensitive-read` | ask | the agent reads a `.env`, key, credential or wallet file (`Read`, `Grep`, `cat` and similar) before the call runs; `.env.example` and similar templates are exempt | the read puts the secret in the model's context, where an injection can use it (`sensitiveReads`: `ask`, `alert`, `off`) |
| `memory-write` | ask | a session that read untrusted content writes a file later sessions trust as instructions (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `CONVENTIONS.md`, `.claude/` commands, rules, memory and skills, `.cursorrules` and similar) | persistent injection: the payload outlives the session |
| `post-denial` | ask | something was already denied and a call goes out | an agent refused once will try another route |
| `self-protection` | deny | a tool call touches the recorder's own data folder | the evidence must not be editable by the agent it records |
| `hook-tamper` | ask | agent settings or plugin files are edited | removing the hooks removes the recorder |
| `risky-mcp` | ask | a tool of an MCP server with high-risk findings in the local audit | a poisoned or over-privileged server |
| `risky-skill` | ask | a skill with high-risk findings is loaded | a skill is instructions the agent will follow |

## Tuning

`~/.blackbox/config.json` controls `memoryWrites` (`ask`, `alert`, `off`), `trustedDocs`, `failMode`, `askFallback`. `blackbox docs` lists the instruction documents the recorder marked as written under taint, and `blackbox docs --clear PATH` (or `--clear-all`) marks them trusted after you review them.

## Adding a rule

1. Implement it in `src/policy.js` with a reason a human can read.
2. Add attack and benign cases to `eval/corpus.js`; the benign set must keep 0 false alarms.
3. Add a unit test, list it in `src/agent-api.js`, and add a row above.
