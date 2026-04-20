---
name: add-helper
description: Add a new server-software helper (config generator) to ssl-config-generator. Wraps the canonical "Adding a new helper" recipe in AGENTS.md with a short checklist and pointers.
---

# add-helper

The canonical, authoritative recipe lives in
[`AGENTS.md`](../../../AGENTS.md) under **"Adding a new helper"**. Read
that section first and follow it verbatim — this skill exists only as a
quick-reference checklist and a place for shortcuts that don't belong in
the top-level guide.

## When to run

A user asks to "add a helper for X", "support generating configs for X",
"add a new server / TLS stack to the generator", or similar.

## Checklist

1. **Pick a key.** Short, lowercase, no spaces (`openldap`, `caddy`, `iis`).
   Becomes the URL fragment value, the filename stem in
   `src/js/helpers/`, the test filename in `test/`, and the radio-button
   value (which `index.ejs` generates automatically by iterating
   `configs.js`).

2. **Add the `configs.js` entry.** The header comment of
   `src/js/configs.js` documents every capability flag; defaults that
   commonly need to be flipped:

   - `usesOpenssl: false` for stacks with their own TLS implementation
     (Go/crypto/tls, rustls, Schannel, s2n-tls).
   - `supportsHsts: false` for non-HTTP servers (Postfix, Dovecot,
     OpenLDAP, Coturn, MySQL, PostgreSQL, …).
   - `supportsCipherSelection: false` for "named-policy" servers
     (AWS ALB/ELB, s2n-tls).
   - `supportsCurveSelection: false` when the server has no per-curve
     directive.
   - `supportsOcspStapling`: a min-version string (e.g. `'2.4.13'`)
     when the feature was added in a specific release.
   - `cipherFormat`: `'iana'` (Schannel/Java/rustls) or `'go'`
     (Go/Caddy/Traefik) when not OpenSSL.
   - `supportsPq`: **opt-in only** — set the first-PQ release version
     string *after* you implement one of the three PQ surfaces below.

3. **Write `src/js/helpers/<key>.js`.** Default-export
   `(form, output) => string`. Lead with a header comment that names
   every emitted directive, the version that introduced it, the
   upstream doc URL (add a BibTeX entry to
   `src/static/citations.bib`), and any PQ caveats.

4. **Pick a PQ strategy** (only if the server has any PQ surface):
   - **Group token** — emit the IANA hybrid-group name
     (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`)
     in the server's group/curve directive.
   - **Comment** — when no group knob exists or the version is too old:
     emit a `# WARNING:` / `# Post-quantum:` block explaining the gap
     and which version unlocks it.
   - **Managed-policy alias** — for vendors with named "policies"
     (s2n-tls, AWS ALB), select the PQ-capable preset.

   **Never silently fall back to "all groups"** — see the gnutls helper
   header for the rationale.

5. **Add `test/<key>.test.js`** using the shared harness:

   ```js
   import { runStandardHelperSuite } from './_helpers/harness.js';
   import myhelper from '../src/js/helpers/myhelper.js';

   runStandardHelperSuite({
     name: 'myhelper',
     helper: myhelper,
     serverVersion: '<latest>',
     cipherFormat: 'openssl',           // or 'iana' / 'go'
     supportsHsts: false,               // when applicable
     supportsPq: true,                  // when applicable
     protocolDirective: {
       modern:       /\bMyMin\b TLSv1\.3/,
       intermediate: /\bMyMin\b TLSv1\.2/,
       old:          /\bMyMin\b TLSv1\b/,    // state.js emits 'TLSv1', not 'TLSv1.0'
     },
   });
   ```

   Per-helper opt-outs require either `notApplicable: true` or a
   `warning: /regex/` — silent skips throw.

6. **Add helper-specific assertions** for directives unique to your
   server (file paths, magic enum values, version-gated branches).

7. **Tests that need an external tool** (e.g. shelling out to `pwsh` or
   `python3` to AST-parse the rendered config) follow the
   *probe-once / skip-with-reason* pattern documented in AGENTS.md
   "Tests that depend on external tools".

8. **Generate the snapshot fixtures** for the new helper:

   ```bash
   npm run render-grid -- --server <key>
   ```

   This writes `fixtures/grid/<key>/<key>__g…__v…__…` files; commit
   them. Subsequent `npm test` runs will assert byte-equality
   re-renders.

9. **Run the full suite and validators:**

   ```bash
   npm test
   ```

   Then invoke `parallel_validation` (Code Review + CodeQL).

## Things you do NOT need to do

- Edit `src/templates/index.ejs` to add a radio button — `index.ejs`
  iterates `configs.js`, so a new entry with a `name:` field shows up
  automatically.
- Edit `src/js/grid-axes.js` — `SERVERS` is derived from `configs.js`.
- Edit any per-server CSS — the page styles are generic.

## Common mistakes (caught only by humans / end-to-end tools)

- **PowerShell:** variables are case-insensitive — never give an inner
  local the same name as a parameter under a different case
  (`$RegPath` vs `$regPath` are the same variable). See
  `src/js/helpers/iis.js`.
- **TLS-version naming:** `state.js` emits `'TLSv1'` (not `'TLSv1.0'`)
  for the `old` profile floor; helpers that need `TLSv1.0` for their
  own directive (HAProxy `ssl-min-ver`) must map it explicitly.
- **`@SECLEVEL=0`:** for OpenSSL ≥ 3.0 in the `old` profile, `state.js`
  prepends `@SECLEVEL=0` to the cipher list — don't strip it.
- **PQ-only mode:** `state.js` forces `protocols = ['TLSv1.3']` when
  `pqMode === 'only'`, but a PQ-aware helper should still defensively
  pin its own minimum-version directive to TLSv1.3 in that mode.
