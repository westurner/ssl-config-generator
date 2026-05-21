# TLS Configurator

The TLS Configurator is a tool which builds configuration files to help you follow the TLSRef [Server Side TLS](https://docs.tlsref.org/Security/Server_Side_TLS) configuration guidelines.

This tool is built and deployed to https://configurator.tlsref.org/

To be notified when the TLSRef [Server Side TLS](https://docs.tlsref.org/Security/Server_Side_TLS) configuration guidelines are updated (infrequent), use github notifications to subscribe to Releases on this repository (tlsref/configurator).

To modify and build this tool locally, please see Installation and Development sections below.

## JSON guidelines

Each revision of the TLSRef Server Side TLS guidelines is published in a machine-readable format as a [JSON specification](https://data.tlsref.org/src/static/guidelines/) 📟

## Contributing

The project is written in JavaScript, and uses Webpack for development and production builds.

We keep a list of things that would make a great contribution tagged with [*help wanted*](https://github.com/tlsref/configurator/labels/help%20wanted), [*good first issue*](https://github.com/tlsref/configurator/labels/good%20first%20issue), and [*new software support*](https://github.com/tlsref/configurator/labels/new%20software%20support) labels.

If you'd like to see your favorite tool added or compatibility expanded, we're always happy to mentor a PR or receive a bug report to make the configs better for everyone.

Even when you don't feel comfortable contributing actual templates, posting some nice verified configs or compatibility hints is equally welcome! 💝

Get involved by sharing your ideas or joining the conversation in the [Discussions](https://github.com/tlsref/configurator/discussions) tab. 🗨️

This repository is governed by Mozilla's [Community Participation Guidelines](/CODE_OF_CONDUCT.md)
so please make yourself familiar with it to get the idea of what level of developer etiquette and standards are expected.

## Installation

NodeJS and npm are required to install and run the project locally:
Node v24 is recommended and we use that in production, but the codebase may be compatible with other versions too.

```bash
$ npm install
```

## Development

Once you've installed, you can simply run:

```bash
$ npm start   # or: npm run watch
```

This starts a local webserver that will automatically reload your changes.

Alternatively, you can use [Docker](https://www.docker.com/) to run the local webserver to avoid
cluttering your local environment with npm dependencies. You first need to build the docker:

```bash
docker build -t moz-ssl-config-gen:latest .
```

You can then run the webserver:

```bash
docker run -p 3001:3001 -p 5500:5500 moz-ssl-config-gen:latest
```

## Adding new software

There are two places that need to be updated in order to add support for a new piece of software:

* `src/js/configs.js`, which sets the supported features for your software, and
* `src/js/helpers/your-software.js`, javascript module which outputs your software's configuration

### Creating templates

All of the templates are written in javascript.  The configuration generator supports the following additional helpers:

- `minpatchver(minimum_ver, cur_ver)` - `true` if `cur_ver` is greater than or equal to `minimum_ver`, AND both versions are the same major/minor version, e.g. `2.4`
  - `minpatchver("2.4.3", form.serverVersion)`
- `minver(minimum_ver, cur_ver)` - `true` if `cur_ver` is greater than or equal to `minimum_ver`
  - `minver("1.9.5", form.serverVersion)`

### Template variables

Highlighted items from src/js/state.js for use in templates.  See src/js/state.js for more.

#### `form.*` (user input)

- `form.server` - selected server key (e.g. `"nginx"`, `"caddy"`, `"python"`)
- `form.serverName` - display name of the server
- `form.serverVersion` - requested server version
- `form.opensslVersion` - requested OpenSSL version
- `form.config` - configuration name (`"modern" | "intermediate" | "old"`)
- `form.hsts` - HTTP Strict Transport Security form checkbox (boolean; gated by `output.supportsHsts`)
- `form.ocsp` - OCSP Stapling form checkbox (boolean; gated by `output.supportsOcspStapling`)
- `form.pq` - Post-Quantum mode (`"none"` = classical only, `"hybrid"` = hybrid PQ + classical, `"only"` = PQ groups only)
- `form.version_tags` - HTML-escaped version string used in the header (e.g. `"nginx 1.27.0, OpenSSL 3.5.0, intermediate config, PQ: hybrid"`)

#### `output.*` (derived state)

General / metadata

- `output.header` - description of rendered config (date, guideline version, version tags, HSTS/OCSP markers)
- `output.link` - URL to rendered config
- `output.fragment` - URL fragment portion of `output.link` (without leading `#`)
- `output.origin` - origin of the generator URL (scheme + host)
- `output.date` - ISO date (`YYYY-MM-DD`) the config was generated
- `output.latestVersion` - server's latest known version (from `configs.js`)
- `output.hasVersions` - server has multiple selectable versions (boolean)

Protocols & ciphers

- `output.protocols` - protocol list (zero or more of `"TLSv1"` `"TLSv1.1"` `"TLSv1.2"` `"TLSv1.3"`); forced to `["TLSv1.3"]` in PQ-only mode
- `output.ciphers` - TLSv1.2 (and older) cipher list (OpenSSL or IANA names depending on the server's `cipherFormat`)
- `output.cipherSuites` - TLSv1.3+ cipher suites list
- `output.serverPreferredOrder` - enforce ServerPreference for ordering cipher list (boolean)
- `output.tlsCurves` - groups/curves list, filtered by the selected PQ mode
- `output.pqMode` - same value as `form.pq`, exposed for use in templates

HSTS / OCSP

- `output.hstsMaxAge` - `max-age` (seconds) for the `Strict-Transport-Security` HTTP response header
- `output.hstsRedirectCode` - HTTP status code to use for HSTS redirect from `http://` to `https://`

Diffie-Hellman

- `output.usesDhe` - server might use (≤ TLSv1.2 kDHE) Diffie-Hellman key exchange (boolean)
- `output.dhCommand` - command to fetch RFC 7919 Diffie-Hellman parameters
- `output.dhParamSize` - DH parameter size in bits (e.g. `2048`)

OpenSSL

- `output.usesOpenssl` - server uses OpenSSL (boolean)

Capability flags (`supports*`) — sourced from `src/js/configs.js` and used by templates and tests to gate sections, banners, and assertions:

- `output.showSupports` - emit the "supports …" footer block describing OS / library prerequisites (boolean; default `true`)
- `output.supportsHsts` - server can emit HSTS headers (boolean; default `true`)
- `output.supportsOcspStapling` - server version (per `configs.js` minimum) supports OCSP Stapling (boolean; falsy when the running version predates support)
- `output.supportsCipherSelection` - server lets the user pin TLS ≤ 1.2 cipher suites (boolean; default `true`)
- `output.supportsCurveSelection` - server lets the user pin key-exchange groups/curves (boolean; default `true`)
- `output.supportsPq` - server has been declared PQ-aware in `configs.js` (boolean; default `false`, opt-in only). When `true`, the test harness asserts the helper emits an `MLKEM` token or PQ-related comment.

Other

- `output.oldestClients` - human-readable list of oldest interoperable clients (from the Mozilla guideline)

### Requested but not yet added new software support

Over time support for various software has been requested and discussed. This is a list of those requests. Check out the linked tickets to see the background and then feel free to submit a pull request for the tool to support that piece of software

* [Microsoft Internet Information Services (IIS)](https://github.com/mozilla/ssl-config-generator/issues/54)
* [Envoy Proxy](https://github.com/mozilla/ssl-config-generator/issues/29)
* [Wildfly](https://github.com/mozilla/ssl-config-generator/issues/172)
* [Kestrel/ASP.NET Core](https://github.com/mozilla/ssl-config-generator/issues/147)
* [OpenLDAP](https://github.com/mozilla/ssl-config-generator/issues/118)
* [GnuTLS](https://github.com/mozilla/ssl-config-generator/issues/321)
* [Exim](https://github.com/mozilla/ssl-config-generator/issues/115)
* [H2O](https://github.com/mozilla/ssl-config-generator/issues/329)
* [Kubelet](https://github.com/mozilla/ssl-config-generator/pull/197)

Active issues related to new software can be found in the issue list using the [`new software support` label](https://github.com/tlsref/configurator/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22new%20software%20support%22).

## Building

Production builds have different CSP headers, included scripts, and version info added to the output, so to verify that locally you can inspect the exact production-level artifacts as used in deployment after running:


```bash
$ npm run build
```

However, this step is not necessary for production deployment.
Automation publishes the production site via GitHub Pages, so once your PR merges the changes deploy within a minute or two.
GitHub Pages are published upon commit to the master branch
via .github/workflows/deploy-to-production.yml

## Tests

Unit tests for individual server-config templates live under [`test/`](test/) and
run with Node's built-in test runner:

```bash
$ npm test
```

Tests are written as standard `node:test` files; `@babel/register` is loaded so
the test runner can `import` the ES-module helpers in `src/js/helpers/`. New
templates should ship with at least one test that asserts the shape of the
generated config (key directives, version-gated comments, PQ-mode behaviour).

## Off-line rendering tools

Two helper scripts under [`scripts/`](scripts/) drive the same renderer
that powers the live site (`src/js/render.js`), so their output is
byte-identical to what the deployed page would produce for the same
URL fragment. Both are wrapped by `npm` aliases for convenience.

### `scripts/render-grid.js` — config snapshot fixtures

```bash
npm run render-grid                              # regenerate every cell
npm run render-grid -- --server nginx            # restrict to one helper
npm run render-grid -- --only-changed            # write only cells that differ
npm run render-grid -- --dry-run                 # print what would be written
```

`render-grid` materialises the *helpers × parameters* grid as a tree of
exact-output snapshot files under
[`fixtures/grid/`](fixtures/grid/), one file per
`(server, guideline, serverVersion, profile, pqMode, hsts, ocsp)` cell.
Each file's name encodes its cell, e.g.
`fixtures/grid/nginx/nginx__g5.7__v1.27.0__intermediate__pq-hybrid__hsts1__ocsp1.conf`.
[`test/grid.test.js`](test/grid.test.js) re-renders every cell on each
`npm test` run and asserts byte-equality against the committed file —
a one-character drift in any helper's output shows up as a one-line
`git diff` reviewers can read directly.

The runtime `generated YYYY-MM-DD …` header date is pinned to a fixed
value (`1970-01-01`), so re-running the script on a different day does
**not** churn every file. `--only-changed` keeps the diff focused on
the cells your edit actually moved; `--dry-run` is useful when you
just want to know *whether* a change is grid-affecting.

Always update fixtures with this script — never hand-edit files under
`fixtures/grid/`. Filename axes (servers, profiles, PQ modes,
guidelines) are defined in [`src/js/grid-axes.js`](src/js/grid-axes.js),
which is the single source of truth shared by the script and the test
suite. Note that guideline 6.0 has no `old` profile; the grid skips
those cells automatically.

### `scripts/screenshot.js` — visual snapshots of the rendered page

```bash
# One-time setup (Playwright is in devDependencies; install Chromium):
npx playwright install chromium

# Capture the default cell (nginx @ latestVersion, intermediate, PQ hybrid):
npm run screenshots

# Pin every axis explicitly and capture the full scrolling page:
npm run screenshots -- \
  --server nginx --config intermediate --pq hybrid --full-page \
  --out fixtures/screenshots/nginx-intermediate-hybrid.png

# Print the full flag list:
npm run screenshots -- --help
```

`screenshot.js` drives the live UI in headless Chromium (it auto-starts
`npm start` on http://localhost:5500, navigates with the URL fragment
that selects your cell, waits for `<pre id="output-config">` to render,
and tears the dev server back down). It is **opt-in** — the
`npm run screenshots` alias sets the required `SCG_GEN_SCREENSHOTS=1`
environment variable for you — because Playwright + Chromium is heavy
and image diffs are noisy (font hinting, AA, scrollbar widths, the
header date in the rendered config). For the same reasons,
[`fixtures/screenshots/`](fixtures/screenshots) is gitignored and
`npm run screenshots` is intentionally **not** part of `npm test`;
review captures locally or attach them to a PR comment. If you need a
PNG that *is* tracked in git (for example to use in this README), pass
`--out` with a path outside the gitignored trees (the repository root
works for a single hero image).

For agents, the [`generate-screenshot` skill](.agents/skills/generate-screenshot/SKILL.md)
documents the full workflow, including the optional flow for refreshing
a README screenshot.

## Post-Quantum (PQ) cryptography

The generator includes a **Post-Quantum Mode** selector with three options:

* **Non-PQ** — classical curves only (e.g. `X25519`, `prime256v1`, `secp384r1`); maximum interoperability with older clients.
* **Hybrid** *(default)* — hybrid PQ + classical groups (e.g. `X25519MLKEM768`) listed alongside classical curves, matching the Mozilla guideline ≥ 5.8.
* **PQ Only** — PQ / hybrid PQ groups only; may break clients that don't yet implement ML-KEM.

PQ key exchange requires a recent TLS library (e.g. OpenSSL ≥ 3.5, BoringSSL, Go ≥ 1.24, GnuTLS ≥ 3.8.10, rustls ≥ 0.23.18). When `Hybrid` or `PQ Only` is selected with an OpenSSL version older than 3.5.0, the generator emits a warning in the configuration header.

### `MinProtocol` in the generated `openssl.cnf`

The new **OpenSSL config (`openssl.cnf`)** software entry produces an `openssl.cnf` snippet that applies system-wide to OpenSSL-based programs, including Python's `ssl` module, curl, libpq, and Rust apps that link the `openssl` crate. (Pure-Rust apps that use `rustls` do **not** honour `openssl.cnf`; use the **Rust (rustls)** target instead.)

For Python applications that prefer to configure TLS in code (rather than rely on the system-wide `openssl.cnf`), the generator also exposes a dedicated **Python (`ssl` module)** target. It emits an `ssl.SSLContext` with `minimum_version` / `maximum_version`, `set_ciphers()`, and `set_groups()` (Python 3.13+, with a `set_ecdh_curve()` fallback for older interpreters). TLSv1.3 ciphersuites are not exposed by the Python API and continue to be inherited from `openssl.cnf`.

The snippet's `MinProtocol` directive mirrors the chosen Mozilla profile rather than always being `TLSv1.3`:

| Profile         | `MinProtocol` |
| --------------- | ------------- |
| `modern`        | `TLSv1.3`     |
| `intermediate`  | `TLSv1.2`     |
| `old`           | `TLSv1`       |

Pick **modern** in the form if you want `MinProtocol = TLSv1.3`. The `intermediate` profile intentionally keeps TLS 1.2 enabled for legacy clients that have not yet migrated to TLS 1.3.

### Hybrid-mode downgrade risk

In `Hybrid` mode the server still negotiates classical groups when a peer advertises only classical groups. A network attacker who can strip the hybrid groups from `ClientHello` can therefore force a classical handshake. If you need to refuse such fallbacks, choose `PQ Only` (and accept the resulting interop loss for clients that don't yet support ML-KEM).

### Browser / library PQ support

Authoritative trackers (mirrored in [`src/static/citations.bib`](src/static/citations.bib)):

* Cloudflare — [PQC support across browsers and libraries](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/)
* Chrome Status — [ML-KEM key agreement](https://chromestatus.com/feature/5076669125558272) (shipped by default in Chrome 131)
* Firefox — [Bug 1933731 — implement X25519MLKEM768](https://bugzilla.mozilla.org/show_bug.cgi?id=1933731)

### Merkle Tree Certificates

[Merkle Tree Certificates](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/) are an emerging IETF proposal to amortise the size of PQ certificate chains. They are not yet deployable end-to-end, so this generator does **not** expose a Merkle-certs mode selector; the PQ mode setting only affects the negotiated key-exchange (KEM) groups, not certificate signatures. See Cloudflare's [Another look at post-quantum signatures](https://blog.cloudflare.com/another-look-at-pq-signatures/) for background.

The relevant specifications and library release notes are collected in BibTeX at [`src/static/citations.bib`](src/static/citations.bib) (NIST FIPS 203 ML-KEM, `draft-kwiatkowski-tls-ecdhe-mlkem`, OpenSSL 3.5 release notes, Apache `mod_ssl`, nginx, Caddy, Traefik, Go `crypto/tls`, GnuTLS, rustls, Python `ssl`, Mozilla Server-Side TLS, Cloudflare PQ posts, Chrome Status / Firefox Bugzilla browser tracking, the Merkle-tree-certs draft, and the originating issue [#342](https://github.com/mozilla/ssl-config-generator/issues/342)).

## History

The SSL Config Generator was originally part of [`mozilla/server-side-tls@v5.0`](https://github.com/mozilla/server-side-tls/tree/12fda41) ([last-revision-before-move](https://github.com/mozilla/server-side-tls/tree/last-revision-before-move))
prior to mid-2019 at which point it was moved to this dedicated repository. It
was initially created [at the end of 2014](https://github.com/mozilla/server-side-tls/commit/b201a11)
and [started out supporting Apache HTTP, Nginx and HAProxy](https://web.archive.org/web/20141026012016/https://mozilla.github.io/server-side-tls/ssl-config-generator/).

## Authors

* [April King](https://github.com/april)
* [Gene Wood](https://github.com/gene1wood)
* [Julien Vehent](https://github.com/jvehent)
* [Glenn Strauss](https://github.com/gstrauss)

## License

This software is licensed under the [MPL version 2.0](https://www.mozilla.org/MPL/). For more
information, read this repository's [LICENSE](LICENSE).
