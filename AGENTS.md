# AGENTS.md

Guide for anyone, human or AI agent, changing this repository. For using the tool, read [README.md](README.md) and [docs/AGENT-GUIDE.md](docs/AGENT-GUIDE.md). For how it is built, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What this is

A tamper-evident flight recorder and prompt-injection firewall for AI coding agents. TypeScript, compiled to plain JavaScript with `tsc`. **Zero runtime dependencies**, Node 18 or newer.

## Commands

| Command | Does |
|---|---|
| `npm test` | builds `dist/`, then runs `node --test test/*.test.js` against it |
| `npm run typecheck` | `tsc -p tsconfig.json` (lenient) and `tsc -p tsconfig.strict.json` (`noImplicitAny`) |
| `npm run build` | compiles `src/`, `bin/`, `eval/` into `dist/` |
| `npm run build:check` | fails if the committed `dist/` is stale |
| `npm run bench` | latency budgets (hook, policy, ledger); runs the compiled copy, so build first |
| `npm run eval` | replays the attack corpus; reports attacks caught and false alarms |

## Rules of the repository

1. **`dist/` is committed.** The plugin, the Homebrew formula and `npx` run it without a build. After any change under `src/`, `bin/` or `eval/`, run `npm run build` and commit `dist/` in the same change. Never resolve a `dist/` merge conflict by hand: take either side, then rebuild.
2. **Tests run against `dist/`**, so `npm test` rebuilds first.
3. **No runtime dependencies.** `typescript` is a dev dependency only. Do not add a package to `dependencies`.
4. **New code is typed.** `tsconfig.strict.json` (`noImplicitAny`) covers everything under `src/`, `bin/`, `eval/` and `bench/` by glob, so a new file is checked from the start. Write new modules in TypeScript (`.ts`); shared shapes live in `src/types.d.ts`.
5. **A change ships with its test**, in the same PR. A policy rule also ships with attack and benign cases in `eval/corpus.ts`; the eval must keep 0 false alarms on the benign set.
6. **Small PRs, one concern each**, on a new branch. Merge only when CI is green on Node 18, 20 and 22.
7. **Docs, comments, commit messages and PR bodies are in English.**
8. **Document everything you work on, and capture repeat procedures as skills.** A feature, fix, decision or workflow change updates the docs that describe it (this file, `docs/`, `README.md`, `CHANGELOG.md`) in the same PR, or in a companion micro-PR. A procedure done more than once becomes a skill under `.claude/skills/<name>/SKILL.md`. Context lives in the repository, never only in a conversation. See [Skills](#skills).

## Invariants not to break

- The recorder (daemon) is a separate process from the agent and the only holder of the signing key. Hooks forward events; they never decide alone.
- Secrets are scrubbed before anything is written. The policy sees the raw event first (to learn which values are secrets), then only a scrubbed copy reaches disk.
- Hooks never exit non-zero because the recorder is down: the event is spooled, or the call fails closed when `failMode` is `closed`.
- The ledger is append-only and hash-chained. Do not add a code path that rewrites a record. Erasing is done by destroying a session key (`purge`), which leaves the chain verifiable.
- A detection rule needs a reason a human can read in the prompt that asks them; a rule that cannot explain itself does not ship.
- Nothing is sent over the network by default. Anything that publishes (anchoring, share, export) is opt-in.

## Skills

Repo skills are short, step-by-step procedures for work this project does repeatedly, so a new session does not have to rediscover them. They live in `.claude/skills/<name>/SKILL.md`, with a frontmatter `name` and a `description` that says when to use the skill.

| Skill | Use it when |
|---|---|

Write or update a skill when:

- you did a procedure a second time, or expect someone to;
- a PR changes the steps of an existing skill (update the skill in that PR);
- you hit a trap that cost time (put it in the skill's "Traps" list).

A skill states the commands, the files it touches and what "done" looks like, grounded in the real code. Add it to the table above in the same PR.

## Where things are

See the module map in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Rules and their rationale: [docs/RULES.md](docs/RULES.md). Agent adapters: [docs/AGENTS.md](docs/AGENTS.md).

## Before you open a PR

```sh
npm run build && npm run typecheck && npm test && npm run build:check
npm run eval
```
