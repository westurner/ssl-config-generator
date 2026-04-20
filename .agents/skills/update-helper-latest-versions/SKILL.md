---
name: update-helper-latest-versions
description: Refresh the per-helper `latestVersion` strings in `src/js/configs.js` against upstream release feeds, then regenerate the snapshot grid and a screenshot of the rendered page.
---

# update-helper-latest-versions

Each helper in `src/js/configs.js` declares a `latestVersion:` string that
the live UI uses as the default value of the "Server Version" input and
that `scripts/render-grid.js` / `scripts/screenshot.js` use as the default
when no `--version` flag is given. Those values drift as upstream
projects cut new releases. This skill walks an agent through refreshing
them.

## When to run

- A user asks to "bump latest versions", "refresh helper versions",
  "check for upstream releases", or similar.
- A periodic maintenance pass before a release of this site.

## Procedure

1. **Open `src/js/configs.js`** and list the current `latestVersion`
   for every helper (one `grep -n latestVersion src/js/configs.js`
   gives the full table).

2. **For each helper, fetch the upstream release feed below** and pick
   the newest *stable* (non-RC, non-beta, non-alpha) version. Prefer
   GitHub release pages or the project's own changelog/announcement
   page over package-manager mirrors so the version string matches what
   `helpers/<name>.js` already gates on with `minver()` /
   `minpatchver()`.

3. **Update only the fields you can verify.** If a project's
   release feed is unreachable, leave the value alone and note it in
   your final summary — do *not* guess.

4. **Update related fields** when an entry has them:
   - `eolBefore` — bump to the oldest still-supported branch when the
     upstream EOL list changes (see the project's "Supported versions"
     page).
   - `tls13` — only when a release *adds* TLS 1.3 support; almost never
     changes for mature helpers.
   - `supportsPq` — bump only when the version that *first* shipped
     ML-KEM hybrid support changes (rare; per `configs.js` header these
     are pinned to the actual first-PQ release).

5. **Re-render the grid snapshots** because `latestVersion` doesn't
   appear in the rendered config, but **only the cells that actually
   changed** should land in `git diff`:

   ```bash
   npm run render-grid -- --only-changed
   ```

   If there is no diff, the bump didn't affect any rendered output —
   that is expected for most helpers (the rendered snapshot is
   indexed by the *requested* version, not by `latestVersion`).

6. **Run the full test suite** to make sure nothing regressed:

   ```bash
   npm test
   ```

7. **Render a screenshot of the page and the helpers table** so the
   reviewer can sanity-check the version values that surface in the UI.

   ```bash
   npm install --save-dev playwright       # one-time
   npx playwright install chromium         # one-time
   npm run screenshots -- --server nginx --pq hybrid --full-page \
     --out fixtures/screenshots/page__nginx__pq-hybrid.png
   npm run screenshots -- --server apache --config intermediate --full-page \
     --out fixtures/screenshots/page__apache__intermediate.png
   ```

   `--full-page` is required to capture the
   "Supported software & capabilities" table at the bottom of the page
   (`#helpers-table-container` in `src/templates/index.ejs`), which is
   the human-readable view of every `latestVersion` you just touched.
   These PNGs are gitignored — attach them to the PR description, do
   not commit them.

8. **Run `parallel_validation`** before finalising.

## Upstream version sources

Use these URLs as the authoritative source for each helper's
`latestVersion`. Prefer the *first* URL listed when a project has
multiple feeds (it is usually the most concise machine-readable one).

| Helper key       | Upstream project         | Primary URL |
| ---------------- | ------------------------ | ----------- |
| `apache`         | Apache httpd             | https://httpd.apache.org/download.cgi  ·  https://downloads.apache.org/httpd/ |
| `awsalb`         | AWS ALB security policies | https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html |
| `awselb`         | AWS Classic ELB policies | https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html |
| `caddy`          | Caddy                    | https://github.com/caddyserver/caddy/releases |
| `coturn`         | coturn                   | https://github.com/coturn/coturn/releases |
| `dovecot`        | Dovecot                  | https://www.dovecot.org/download/  ·  https://github.com/dovecot/core/releases |
| `exim`           | Exim                     | https://www.exim.org/  ·  https://github.com/Exim/exim/releases |
| `go`             | Go (crypto/tls)          | https://go.dev/dl/  ·  https://github.com/golang/go/releases |
| `gnutls`         | GnuTLS                   | https://www.gnutls.org/news.html  ·  https://gitlab.com/gnutls/gnutls/-/releases |
| `haproxy`        | HAProxy                  | https://www.haproxy.org/  ·  https://git.haproxy.org/?p=haproxy.git;a=summary |
| `iis`            | Windows Server / IIS     | https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info  (helper version tracks Windows build, e.g. `10.0.26100` = Server 2025 / Win 11 24H2) |
| `jetty`          | Eclipse Jetty            | https://github.com/jetty/jetty.project/releases  ·  https://eclipse.dev/jetty/download.php |
| `lighttpd`       | lighttpd                 | https://www.lighttpd.net/  ·  https://github.com/lighttpd/lighttpd1.4/releases |
| `litespeed`      | LiteSpeed Web Server     | https://www.litespeedtech.com/products/litespeed-web-server/release-log |
| `mysql`          | MySQL                    | https://dev.mysql.com/doc/relnotes/mysql/9.0/en/  ·  https://www.mysql.com/downloads/ |
| `nginx`          | nginx                    | https://nginx.org/en/CHANGES  ·  https://nginx.org/en/download.html |
| `openssl`        | OpenSSL                  | https://openssl-library.org/source/  ·  https://github.com/openssl/openssl/releases |
| `opensslcnf`     | OpenSSL (config syntax)  | same as `openssl` |
| `openlitespeed`  | OpenLiteSpeed            | https://openlitespeed.org/release-log/  ·  https://github.com/litespeedtech/openlitespeed/releases |
| `openldap`       | OpenLDAP                 | https://www.openldap.org/software/release/changes.html  ·  https://www.openldap.org/software/download/ |
| `oraclehttp`     | Oracle HTTP Server       | https://www.oracle.com/middleware/technologies/webtier-downloads.html |
| `postfix`        | Postfix                  | https://www.postfix.org/announcements.html  ·  https://www.postfix.org/download.html |
| `postgresql`     | PostgreSQL               | https://www.postgresql.org/support/versioning/  ·  https://www.postgresql.org/docs/release/ |
| `proftpd`        | ProFTPD                  | http://www.proftpd.org/  ·  https://github.com/proftpd/proftpd/releases |
| `python`         | CPython (`ssl` module)   | https://www.python.org/downloads/  ·  https://github.com/python/cpython/releases |
| `redis`          | Redis                    | https://github.com/redis/redis/releases  ·  https://redis.io/downloads/ |
| `rust`           | rustls                   | https://github.com/rustls/rustls/releases  (track the `rustls/v0.x.y` tag — the helper is for the rustls crate, not the Rust language) |
| `s2n`            | s2n-tls                  | https://github.com/aws/s2n-tls/releases |
| `squid`          | Squid                    | http://www.squid-cache.org/Versions/  ·  https://github.com/squid-cache/squid/releases |
| `stunnel`        | stunnel                  | https://www.stunnel.org/downloads.html  ·  https://www.stunnel.org/news.html |
| `tomcat`         | Apache Tomcat            | https://tomcat.apache.org/whichversion.html  ·  https://tomcat.apache.org/download-11.cgi |
| `traefik`        | Traefik                  | https://github.com/traefik/traefik/releases |

## Notes

- Some entries deliberately track a non-obvious upstream:
  - `iis` tracks the **Windows build number** (e.g. `10.0.26100`),
    not an "IIS version".
  - `awsalb` / `awselb` track an AWS **security-policy date string**
    (e.g. `2023.3.22`), not a software version — bump only when AWS
    ships a new managed policy.
  - `oraclehttp` tracks Oracle Fusion Middleware bundle versions;
    these change rarely.
- After bumping, double-check that no `helpers/<name>.js` file gates a
  recently-introduced directive on a version *newer* than the new
  `latestVersion`; if it does, the rendered config for `latestVersion`
  may now silently lose that directive on the live site.
