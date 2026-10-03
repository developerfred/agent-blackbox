# Security policy

agent-blackbox is a security tool, so bypasses are the most useful reports we can get.

## Reporting

Please **do not open a public issue** for:

- a way to run an outbound call that the policy should have stopped
- a way to edit, delete or reorder ledger records without `blackbox verify` noticing
- a way for the agent to read the signing key or forge events
- secrets leaking into `ledger.jsonl` in clear text

Use GitHub's private vulnerability reporting (Security tab → "Report a vulnerability"), or email codingsh@pm.me. Include the agent and version, the steps, and what you expected. You will get an answer within 7 days.

## Known limitations

These are documented in the README and are not considered vulnerabilities on their own: the signing key is protected by the OS user rather than hardware, the recorder fails open by default, and secret detection is pattern-based.
