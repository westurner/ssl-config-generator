---
name: update-package-json-versions
description: Bump build/runtime dependencies in `package.json` to their latest compatible releases, then re-run the test suite, build, and validators.
---

# update-package-json-versions

Refresh the entries in the `dependencies` and `devDependencies` blocks
of `package.json`, ideally one logical group at a time, then prove
nothing regressed by running the test suite and a production build.

## When to run

- A user asks to "bump npm deps", "update package.json", "refresh
  dependencies", "run npm outdated", or similar.
- Periodic maintenance, especially after Dependabot opens an upgrade
  PR you want to roll into a wider sweep.

## Procedure

1. **Inventory drift.** From the repo root:

   ```bash
   npm outdated --long
   ```

   The columns are: `Current` (installed), `Wanted` (max satisfying
   the existing semver range in `package.json`), `Latest` (newest
   published). Note which packages are *only* `Current` < `Wanted`
   (free upgrade — same range) vs `Wanted` < `Latest` (would need
   the range bumped).

2. **Check the GitHub Advisory DB before adding or upgrading any
   dependency.** Use the `gh-advisory-database` tool (or
   https://github.com/advisories) for every dependency you intend to
   bump. Skip ecosystems the tool doesn't support; for `npm` (this
   repo), do not skip.

3. **Apply free upgrades first** (those that satisfy the existing
   semver range):

   ```bash
   npm update
   ```

   This rewrites `package-lock.json` only and keeps `package.json`
   ranges intact. Commit the lockfile change separately so the diff
   is reviewable.

4. **For range bumps** (Dependabot-style major/minor jumps), edit the
   version range in `package.json` directly and then:

   ```bash
   npm install
   ```

   Group related packages into one commit (e.g. all `@babel/*`,
   all `webpack*`, etc.) so a regression bisect can revert one
   ecosystem at a time.

5. **Run the full test suite:**

   ```bash
   npm test
   ```

   The runner is Node's built-in `node:test` with `@babel/register`
   preloaded (see `package.json:scripts.test`). It covers:
   - per-helper invariant tests in `test/<helper>.test.js`,
   - the snapshot suite in `test/grid.test.js` (re-renders every
     `fixtures/grid/**` cell and asserts byte-equality).

   If the snapshot suite fails *after* a `@babel/*` or `semver`
   upgrade, suspect formatter/output drift and re-render the grid
   to see whether the diff is real:

   ```bash
   npm run render-grid -- --only-changed
   git diff fixtures/grid/
   ```

   Only commit the regenerated fixtures if the diff is genuinely
   from an intentional renderer/helper change — *not* if it's just
   noise from a transformed dependency.

6. **Run the production build** to catch loader / plugin compatibility
   regressions that the test suite can't see:

   ```bash
   npm run build
   ```

   For deeper inspection of a webpack config drift:

   ```bash
   npm run analyze
   ```

7. **Smoke-test the dev server** (only when changing
   webpack-dev / browser-sync / loader packages):

   ```bash
   npm start &
   # visit http://localhost:5500, exercise the form, then:
   kill %1
   ```

   Use `mode="async", detach: true` if running this in an automated
   environment.

8. **Run `parallel_validation`** (Code Review + CodeQL) before
   finalising. Address any new findings introduced by upgraded
   transitive dependencies.

## Constraints

- **Do not touch lockfile entries by hand** — let `npm` regenerate them.
- **Do not skip `npm test`.** A green build is necessary but not
  sufficient: `webpack --progress` will succeed even when a Babel
  preset upgrade silently changes the emitted JS in a way that breaks
  the helpers' regex assertions.
- **Pin major-version jumps** to a separate commit per ecosystem so
  the PR is bisectable.
- **Do not introduce new top-level tooling** (linter, formatter,
  bundler, test framework) under this skill — it is for *upgrades*,
  not additions. New tooling needs its own task.

## Useful one-liners

```bash
# Just the dev-deps that would jump major versions
npm outdated --long | awk 'NR==1 || $2 != $4'

# Force-resolve a single transitive vulnerability (last resort;
# prefer waiting for the upstream fix):
npm install --save-exact <pkg>@<safe-version>

# Verify every direct dep installs cleanly from scratch
rm -rf node_modules package-lock.json && npm install && npm test
```
