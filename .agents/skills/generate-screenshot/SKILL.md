---
name: generate-screenshot
description: Render a PNG of the live web UI for one parameter set with `scripts/screenshot.js` (Playwright), and optionally update the README hero screenshot to point at the freshly generated image.
---

# generate-screenshot

`scripts/screenshot.js` (npm alias: `npm run screenshots`) drives the
live generator UI in headless Chromium and writes a PNG of the rendered
page for one `(server, version, profile, hsts, ocsp, pq, guideline)`
cell. The script is **opt-in**: it only runs when
`SCG_GEN_SCREENSHOTS=1` is set (the `npm run screenshots` alias sets it
for you), because Playwright + Chromium is heavy and image diffs are
noisy (font hinting, AA, scrollbar widths, the rendered date in the
output header).

The script and the off-line config-grid renderer
(`scripts/render-grid.js`) both call the pure `src/js/render.js`, so
the PNG always reflects the same logic that `npm test` exercises and
that the deployed site emits — there is no separate rendering path to
drift out of sync.

## When to run

A user asks any of:

- "take a screenshot of the page" / "render a screenshot of the UI"
- "update the README screenshot"
- "generate a fresh hero image" / "refresh the README image"
- "show what the current Hybrid PQ output looks like"

…or you (the agent) are about to file a PR whose effect on the rendered
page is easier to convey visually than in prose.

## One-time prerequisites

Playwright is already declared in `devDependencies`, so a normal
`npm install` brings it in. The Chromium browser binary is **not**
installed by `npm install` on its own; install it once per machine:

```bash
npx playwright install chromium
```

If `playwright` itself is somehow missing, `npm install --save-dev
playwright` first.

## Invocation

The script auto-starts `npm start` (webpack + browser-sync on
http://localhost:5500) in the background, waits for it to come up,
loads the page with the URL fragment that selects your cell, waits
until `<pre id="output-config">` has rendered text, and writes the PNG.
Finally it tears the dev server back down. You almost never need to
pass `--base-url`.

```bash
# Defaults: nginx @ latestVersion, intermediate, hsts=true, ocsp=true,
# pq=hybrid, guideline=5.7, output → fixtures/screenshots/<auto>.png
npm run screenshots

# Pin every axis explicitly:
npm run screenshots -- \
  --server nginx --version 1.27.0 --openssl 3.5.0 \
  --config intermediate --pq hybrid --guideline 5.7 \
  --hsts true --ocsp true \
  --full-page \
  --out fixtures/screenshots/nginx-intermediate-hybrid.png
```

Useful flags:

- `--full-page` — capture the whole scrolling page (including the
  "Supported software & capabilities" table at the bottom). Without
  it the script crops to `<main>`.
- `--base-url <url>` — point at an already-running dev server (e.g. an
  external `npm start` on `http://localhost:5500/`) instead of
  spawning one.
- `--wait-ms <n>` — extra settle time after `output-config` first
  appears (default `1500`); increase if the rendered output is large
  or styles are still settling.
- `--out <path>` — destination PNG. The default mirrors the grid
  filename scheme (`fixtures/screenshots/<server>/<server>__g…__v…__…__pq-…__hsts…__ocsp….png`)
  so a screenshot and its config snapshot live side-by-side under
  different extensions.

`npm run screenshots -- --help` prints the full flag list.

## Default output location and `.gitignore`

`fixtures/screenshots/` is **gitignored** on purpose (image diffs are
noisy and bloat the repo). For ad-hoc captures, write into the default
path and review locally / attach to a PR comment.

If you need to **commit** a PNG (e.g. for use in `README.md`), pass
`--out` with a path that is not under `fixtures/screenshots/` (or
`build/`, `node_modules/`, `docs/` — also gitignored). The repository
root is tracked, so `screenshot.png` in the repo root is the simplest
choice for a single hero image:

```bash
npm run screenshots -- --server nginx --pq hybrid --full-page \
  --out screenshot.png
```

## Optional: update the README hero screenshot

If the user asks to refresh / set the README screenshot, follow this
flow:

1. **Generate the PNG to a tracked path.** Pick a stable, descriptive
   filename and write it to a non-gitignored location:

   ```bash
   npm run screenshots -- \
     --server nginx --config intermediate --pq hybrid --full-page \
     --out screenshot.png
   ```

2. **Reference it from `README.md`.** If the README already has a
   screenshot reference, update its `src=` / Markdown image path to
   the file you just wrote. Otherwise add a short subsection near the
   top — for example, just under the project tagline:

   ```markdown
   ![SSL Configuration Generator — nginx, intermediate profile, Hybrid PQ](./screenshot.png)
   ```

   Keep the alt text descriptive of the *captured* parameter set
   (server, profile, PQ mode), so future readers understand why the
   image looks the way it does without re-running the script.

3. **Commit the PNG and the README change together** so the image
   never lands without a corresponding text reference (broken images
   in `README.md` are noisier than no image at all).

4. **Re-run when the captured cell drifts.** The PNG includes the
   rendered config text, so any helper change that affects the chosen
   `(server, profile, pq, …)` cell will eventually make the README
   image stale. Re-run with the same `--out` path to overwrite in
   place.

If the user did *not* ask to update the README, **do not** modify it —
ad-hoc screenshots belong under `fixtures/screenshots/` (gitignored)
and are reviewed locally / attached to PRs as comments.

## Pitfalls

- **`SCG_GEN_SCREENSHOTS=1` is mandatory.** The script exits 64 with a
  hint if it is unset; `npm run screenshots` sets it automatically.
- **The dev server takes several seconds to come up.** `waitForServer`
  polls `http://localhost:5500/` once a second up to 30 s; if your box
  is slow the script will simply wait, not fail prematurely.
- **The header date is non-deterministic in the live page.** Unlike
  the off-line `scripts/render-grid.js`, the live UI uses
  `Date.now()` — re-running the script on a different day will
  produce a one-line PNG diff in the header. This is expected; do not
  chase it. (See the comment block at the top of
  `scripts/screenshot.js` for the full rationale.)
- **Don't commit anything under `fixtures/screenshots/`.** If you need
  a tracked image, pass an explicit `--out` outside that tree.
- **Don't add `npm run screenshots` to CI's default test step.** It
  pulls in Chromium (~150 MB) and is intentionally kept out of
  `npm test`.
