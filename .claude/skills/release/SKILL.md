---
name: release
description: Cut a release of agent-blackbox (bump versions, update CHANGELOG, push a vX.Y.Z tag that the release workflow publishes). Use when asked to release, publish or tag a version.
---

# Release

Releases are tag-driven. Pushing `vX.Y.Z` runs `.github/workflows/release.yml`, which checks, publishes to npm with provenance, and creates the GitHub release.

## Steps

1. Start from an up-to-date `main` and a new branch, for example `release/vX.Y.Z`.
2. In `CHANGELOG.md`, move the entries under "Unreleased" to a new `## X.Y.Z` heading with the date. Leave an empty "Unreleased" section. Before 1.0 a minor bump may change behavior, and the entry must say so.
3. Set the same `version` in `package.json` and `.claude-plugin/plugin.json`. Also run `npm install --package-lock-only` so `package-lock.json` matches.
4. Run the full check, as for any PR: `npm run build && npm run typecheck && npm test && npm run build:check && npm run eval`. Commit `dist/` if it changed.
5. Open a micro-PR with only the release changes. Merge it once CI is green on Node 18, 20 and 22 and the user has approved.
6. Tag the merge commit and push the tag (only with the user's go-ahead, it publishes to npm and cannot be undone):
   ```sh
   git checkout main && git pull
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
7. Watch the `release` run. Its job summary prints the tarball `url` and `sha256` for the Homebrew formula: update the formula under `packaging/` in a follow-up PR.

## What the workflow checks

- The tag (without `v`), `package.json` and `.claude-plugin/plugin.json` versions are all equal, or it fails.
- `build:check`, `npm test`, `typecheck` and `blackbox eval` pass.
- The publish step needs the `NPM_TOKEN` repository secret. Without it nothing is released.

## Traps

- A tag that does not match both manifests fails the run. Delete the tag, fix the versions, tag again.
- Never tag from a branch other than the merged `main`.
- Never edit `dist/` by hand; rebuild.
