---
name: run-eval-and-bench
description: Replay the attack corpus and check the latency budgets of agent-blackbox. Use before a PR that touches the policy, or when asked how many attacks are caught or how fast the hook is.
---

# Run the eval and the bench

Both run the compiled copy in `dist/`, so build first.

## Eval (does the policy still catch attacks, without false alarms?)

```sh
npm run build
npm run eval                                  # = node dist/bin/blackbox.js eval
node dist/bin/blackbox.js eval --agent all    # also the Codex, Cursor and Gemini adapters
```

Read the three numbers: attacks caught (`71/71` at the time of writing), false alarms (must be `0`), and known gaps still open. A false alarm or a missed attack fails the work. Cases live in `eval/corpus.ts`; see the `add-detection-rule` skill to add one.

## Bench (are the hot paths inside budget?)

```sh
npm run build
npm run bench                  # all
node dist/bench/run.js --only <name>
node dist/bench/run.js --json  # machine-readable p50/p95 per path
```

Budgets: policy decision under 1 ms, hook round trip under 20 ms at p95. CI prints the numbers but does not fail on them, because shared runners are noisy. Compare against a run on the same machine from before your change.

## Traps

- Running without `npm run build` measures stale code.
- `blackbox eval` prints a pointer to `eval/corpus.js`; the file is `eval/corpus.ts`.
- Do not put real hosts, keys or payloads in corpus cases: use `*.example` and generated fakes.
