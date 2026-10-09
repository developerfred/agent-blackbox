---
name: add-detection-rule
description: Add or change a policy rule in agent-blackbox, with its reason, eval corpus cases, unit test and docs. Use when adding a detection, closing an evasion or fixing a false alarm.
---

# Add a detection rule

A rule that cannot explain itself to the human in the prompt does not ship.

## Steps

1. **Implement** in `src/policy.ts`, in the pre-tool-use decision (the checks run in order: self-protection, hook-tamper, memory-write, then the egress rules). Return `{ decision: 'ask' | 'deny', rule: '<id>', reason: '<sentence a human can act on>' }`. Use `ask` unless there is no innocent reading, in which case `deny`.
2. **Register** it in the `RULES` list in `src/agent-api.ts` (id, decision, one-line summary). The agent API serves this list at `/v1/agent/rules`.
3. **Corpus**: add cases to `eval/corpus.ts`. Each case has `id`, `before` (earlier events), `call`, `expect: 'block' | 'allow'`. Add at least one attack and one benign look-alike. Hosts are `*.example`, secrets are fakes built in code (see `SECRET`), no real payloads. A way through you cannot close yet gets `gap: true` so it is tracked.
4. **Test**: add a unit test in `test/` (for example next to the `hook-tamper` assertion in `test/blackbox.test.js`) that checks the decision and the `rule` id.
5. **Docs**: add a row to the table in `docs/RULES.md`; if users see it, update `docs/AGENT-GUIDE.md` and the `CHANGELOG.md` "Unreleased" section.
6. **Scan flags**: if the rule should show in `blackbox scan`, add its id to `FLAG_RULES` in `src/scan.ts`.
7. **Verify**: `npm run build && npm run typecheck && npm test && npm run build:check && npm run eval`. The eval must print 0 false alarms on the benign set. Commit `dist/` with the change.

## Traps

- `docs/RULES.md` still says `src/policy.js` and `eval/corpus.js`; the real files are `.ts`.
- The policy sees the raw event first, then only a scrubbed copy reaches disk. Do not log raw values from a rule.
- Do not widen a rule to catch one attack at the cost of benign cases; the false-alarm count is a hard gate.
- Hooks never decide alone and never exit non-zero because the recorder is down.
