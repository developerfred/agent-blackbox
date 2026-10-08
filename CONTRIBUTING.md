# Contributing

Thanks for helping. The short version:

1. Read [AGENTS.md](AGENTS.md): it has the commands, the rules of the repository and the invariants that must not break. It applies to people and to AI agents alike.
2. Work on a new branch and open a small pull request, one concern each.
3. Before you push: `npm run build && npm run typecheck && npm test && npm run build:check`, and `npm run eval`. `dist/` is committed, so commit the rebuilt output with your change.
4. A change ships with its test. A new policy rule also ships with attack and benign cases in `eval/corpus.ts`, and the eval must keep 0 false alarms.

## Found a way past the policy?

Do not open a public issue. Follow [SECURITY.md](SECURITY.md). Once it is fixed, the case goes into the corpus with credit if you want it.

## Found a false alarm?

Open a "False alarm" issue. A harmless command that gets blocked is as important to us as a bypass: it is how people stop trusting the tool.

## Code style

TypeScript with `strict` and `noImplicitAny`; no runtime dependencies (`typescript` is a dev dependency only); comments say why, not what.
