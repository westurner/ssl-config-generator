# Mozilla SSL Configuration Generator

The Mozilla SSL Configuration Generator is a tool which builds configuration files to help you follow the Mozilla [Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) configuration guidelines.

This tool is built and deployed to https://ssl-config.mozilla.org/

To be notified when the Mozilla [Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) configuration guidelines are updated (infrequent), use github notifications to subscribe to Releases on this repository (mozilla/ssl-config-generator).

To modify and build this tool locally, please see Installation and Development sections below.

## JSON guidelines

Each revision of the Mozilla Server Side TLS guidelines is published in a machine-readable format from this repository as a [JSON specification](/src/static/guidelines/) that can be found at [`/src/static/guidelines/`](/src/static/guidelines/) 📟

## Changelog

The [Changelog](/src/static/guidelines/CHANGELOG.md) that tracks the history of changes to Mozilla's configuration guidelines is available along the versioned JSON guideline files at [`/src/static/guidelines/CHANGELOG.md`](/src/static/guidelines/CHANGELOG.md) 🔬

## Contributing

The project is written in JavaScript, and uses Webpack for development and production builds.

We keep a list of things that would make a great contribution tagged with [*help wanted*](https://github.com/mozilla/ssl-config-generator/labels/help%20wanted), [*good first issue*](https://github.com/mozilla/ssl-config-generator/labels/good%20first%20issue), and [*new software support*](https://github.com/mozilla/ssl-config-generator/labels/new%20software%20support) labels.

If you'd like to see your favorite tool added or compatibility expanded, we're always happy to mentor a PR or receive a bug report to make the configs better for everyone.

Even when you don't feel comfortable contributing actual templates, posting some nice verified configs or compatibility hints is equally welcome! 💝

Get involved by sharing your ideas or joining the conversation in the [Discussions](https://github.com/mozilla/ssl-config-generator/discussions) tab. 🗨️

This repository is governed by Mozilla's [Community Participation Guidelines](/CODE_OF_CONDUCT.md)
so please make yourself familiar with it to get the idea of what level of developer etiquette and standards are expected across Mozilla projects.

## Installation

NodeJS and npm are required to install and run the project locally:
Node v22 is recommended and we use that in production, but the codebase may be compatible with other versions too.

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

- `form.serverName` - display name of the server
- `form.serverVersion` - requested server version
- `form.opensslVersion` - requested OpenSSL version
- `form.config` - configuration name ([ "modern" | "intermediate" | "old" ])
- `form.hsts` - HTTP Strict Transport Security form checkbox (boolean true/false)
- `form.ocsp` - OCSP Stapling form checkbox (boolean true/false)
- `output.header` - description of rendered config
- `output.link` - URL to rendered config
- `output.protocols` - protocol list (e.g. zero or more of: "TLSv1" "TLSv1.1" "TLSv1.2" "TLSv1.3")
- `output.ciphers` - TLSv1.2 (and older) cipher list
- `output.cipherSuites` - TLSv1.3+ cipher suites list
- `output.serverPreferredOrder` - enforce ServerPreference for ordering cipher list (boolean true/false)
- `output.hstsMaxAge` - max-age (seconds) for Strict-Transport-Security: max-age=... HTTP response header
- `output.hstsRedirectCode` - HTTP status code to use for HSTS redirect from http:// to https://
- `output.latestVersion` - server latest version
- `output.usesOpenssl` - server uses openssl (boolean true/false)
- `output.usesDhe` - server might use (<= TLSv1.2 kDHE) Diffie-Hellmann key exchange (boolean true/false)
- `output.dhCommand` - command to generate Diffie-Hellman (DH) parameters
- `output.hasVersions` - config supports several server versions (boolean true/false)
- `output.supportsHsts` - supports HTTP Strict Transport Security (HSTS) (boolean true/false)
- `output.supportsOcspStapling` - server version supporting OCSP Stapling in config
- `output.tls13` - server version supporting TLSv1.3
- `output.tlsCurves` - groups/curves list (filtered by the selected PQ mode)
- `form.pq` - Post-Quantum mode (`"none"` = classical only, `"hybrid"` = hybrid PQ+classical, `"only"` = PQ groups only)
- `output.pqMode` - same value as `form.pq`, exposed for use in templates

### Requested but not yet added new software support

Over time support for various software has been requested and discussed. This is a list of those requests. Check out the linked tickets to see the background and then feel free to submit a pull request for the tool to support that piece of software

* [Micorsoft Internet Information Services (IIS)](https://github.com/mozilla/ssl-config-generator/issues/54)
* [Envoy Proxy](https://github.com/mozilla/ssl-config-generator/issues/29)
* [Wildfly](https://github.com/mozilla/ssl-config-generator/issues/172)
* [Kestrel/ASP.NET Core](https://github.com/mozilla/ssl-config-generator/issues/147)
* [OpenLDAP](https://github.com/mozilla/ssl-config-generator/issues/118)
* [GnuTLS](https://github.com/mozilla/ssl-config-generator/issues/321)
* [Exim](https://github.com/mozilla/ssl-config-generator/issues/115)
* [H2O](https://github.com/mozilla/ssl-config-generator/issues/329)
* [Kubelet](https://github.com/mozilla/ssl-config-generator/pull/197)

Active issues related to new software can be found in the issue list using the [`new software support` label](https://github.com/mozilla/ssl-config-generator/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22new%20software%20support%22).

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

## Post-Quantum (PQ) cryptography

The generator includes a **Post-Quantum Mode** selector with three options:

* **Non-PQ** — classical curves only (e.g. `X25519`, `prime256v1`, `secp384r1`); maximum interoperability with older clients.
* **Hybrid** *(default)* — hybrid PQ + classical groups (e.g. `X25519MLKEM768`) listed alongside classical curves, matching the Mozilla guideline ≥ 5.8.
* **PQ Only** — PQ / hybrid PQ groups only; may break clients that don't yet implement ML-KEM.

PQ key exchange requires a recent TLS library (e.g. OpenSSL ≥ 3.5, BoringSSL, Go ≥ 1.24, GnuTLS ≥ 3.8.10, rustls ≥ 0.23.18). When `Hybrid` or `PQ Only` is selected with an OpenSSL version older than 3.5.0, the generator emits a warning in the configuration header.

### `MinProtocol` in the generated `openssl.cnf`

The new **OpenSSL config (`openssl.cnf`)** software entry produces an `openssl.cnf` snippet that applies system-wide to OpenSSL-based programs, including Python's `ssl` module, curl, libpq, and Rust apps that link the `openssl` crate. (Pure-Rust apps that use `rustls` do **not** honour `openssl.cnf`; use the **Rust (rustls)** target instead.)

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

## License

This software is licensed under the [MPL version 2.0](https://www.mozilla.org/MPL/). For more
information, read this repository's [LICENSE](LICENSE).
