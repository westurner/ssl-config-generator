// Shared context-object escape helpers used by every helper in
// src/js/helpers/ that wants to interpolate a `form.*` field into the
// rendered config string.
//
// Convention (see AGENTS.md):
//   * Helpers MUST NOT splice `form.foo` directly into a template
//     string. Instead they build a `ctx` object near the top of the
//     function — one key per substitution site — passing each value
//     through `safe()` (or `xmlEntities()` from utils.js for XML
//     templates) BEFORE it reaches the template. That way every
//     interpolation is sanitised at the same place, and reviewing a
//     template diff for injection risk only requires looking at the
//     helper's `ctx = { ... }` block.
//
// `form.config`, `form.serverVersion`, and `form.opensslVersion` are
// already validated upstream (state.js / render.js) — `safe()` here is
// defence in depth so a future regression in upstream validation can't
// inject newlines, backticks, comment terminators (`*/`), TOML-key
// delimiters (`]`), HTML/XML metacharacters, etc. into the rendered
// output.
//
// The character allow-list `[A-Za-z0-9._+-]` covers every legitimate
// value of these fields:
//   - `config`         – Mozilla profile name (modern|intermediate|old)
//   - `serverVersion`  – semver-shaped string (digits, dots, dashes,
//                        plus/build tags)
//   - `opensslVersion` – same shape as serverVersion
// Any character outside that set is dropped (NOT replaced) so the
// resulting string is safe inside hash comments, C/C++ comments, XML
// comments, TOML/INI keys, JSON string bodies, Python string literals,
// PowerShell here-strings, and shell single-quoted strings — the full
// range of template formats this generator targets.
export const safe = (s) => String(s == null ? '' : s).replace(/[^A-Za-z0-9._+-]/g, '');
