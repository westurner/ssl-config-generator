// Pure (DOM-free) renderer.
//
// pureState() is the byte-for-byte equivalent of the body of state.js, but
// takes a plain JavaScript form-input object and a pre-loaded guideline
// JSON instead of reading from the DOM and async-fetching guidelines.
// Both src/js/state.js (browser) and the off-line generators in scripts/
// (render-grid, screenshot) call this so there is exactly ONE source of
// truth for "form → {form, output}". The downstream helper template in
// src/js/helpers/<server>.js is then `helper(state.form, state.output)`.
//
// Inputs:
//   server          string  configs.js key (e.g. 'nginx', 'iis', …)
//   serverVersion   string  e.g. '1.27.3'
//   opensslVersion  string  e.g. '3.0.0' (ignored when usesOpenssl===false)
//   config          string  'modern' | 'intermediate' | 'old' (Mozilla profile)
//   hsts            bool    raw HSTS checkbox
//   ocsp            bool    raw OCSP-stapling checkbox
//   pqMode          string  'none' | 'hybrid' | 'only'  (default 'hybrid')
//   guideline       string  e.g. '5.7' (selects which JSON is honoured)
//   guidelineData   object  the parsed guideline JSON (caller supplies)
//   origin          string  e.g. 'https://example.invalid' (for link / dh url)
//   pathname        string  e.g. '/' (for link)
//   now             Date    used for the `generated YYYY-MM-DD …` header
//                           (callers wanting deterministic output pin this)

import configs from './configs.js';
import minver from './helpers/minver.js';
import { xmlEntities } from './utils.js';

export default function pureState({
  server,
  serverVersion,
  opensslVersion,
  config,
  hsts,
  ocsp,
  pqMode,
  guideline,
  guidelineData,
  origin = 'https://ssl-config.mozilla.org',
  pathname = '/',
  now = new Date(),
}) {
  const sstls = guidelineData;
  const ssc = sstls.configurations[config];

  const supportsOcspStapling =
    configs[server].supportsOcspStapling
    && minver(configs[server].supportsOcspStapling, serverVersion);

  // Post-Quantum mode: 'none' (classical only), 'hybrid' (default), 'only' (PQ groups only).
  // See src/static/citations.bib for the relevant specifications and library
  // release notes (NIST FIPS 203 ML-KEM, draft-ietf-tls-hybrid-design,
  // draft-kwiatkowski-tls-ecdhe-mlkem, OpenSSL 3.5 release notes, etc.).
  let pqEffective = pqMode || 'hybrid';
  if (pqEffective !== 'none' && pqEffective !== 'hybrid' && pqEffective !== 'only') {
    pqEffective = 'hybrid';
  }
  const isPqGroup = (g) => /MLKEM/i.test(g);

  // generate the fragment (matches state.js: omit pq= when 'hybrid')
  let fragment = `server=${server}&version=${serverVersion}&config=${config}`;
  fragment += configs[server].usesOpenssl !== false ? `&openssl=${opensslVersion}` : '';
  fragment += configs[server].supportsHsts !== false && hsts ? '&hsts' : '';
  fragment += supportsOcspStapling && ocsp ? '&ocsp' : '';
  fragment += `&guideline=${guideline}`;
  if (pqEffective !== 'hybrid') {
    fragment += `&pq=${pqEffective}`;
  }

  // generate the version tags
  let version_tags = `${configs[server].name} ${serverVersion}`;
  if (configs[server].eolBefore && !minver(configs[server].eolBefore, serverVersion)) {
    version_tags += ' (UNSUPPORTED; end-of-life)';
  }
  if (configs[server].usesOpenssl !== false) {
    version_tags += `, OpenSSL ${opensslVersion}`;
    if (!minver(configs['openssl'].eolBefore, opensslVersion)) {
      version_tags += ' (UNSUPPORTED; end-of-life)';
    } else if (!minver('3.5.0', opensslVersion) && minver('5.8', guideline)) {
      version_tags += ' (OLD: missing PQC hybrid MLKEMs)';
    }
  }
  version_tags += `, ${config} config`;
  if (pqEffective === 'none') {
    version_tags += ', PQ: none';
  } else if (pqEffective === 'only') {
    version_tags += ', PQ: only';
  } else {
    version_tags += ', PQ: hybrid';
  }
  if (pqEffective !== 'none'
      && configs[server].usesOpenssl !== false
      && !minver('3.5.0', opensslVersion)) {
    version_tags += ' (WARNING: OpenSSL < 3.5.0 lacks built-in ML-KEM)';
  }

  version_tags = xmlEntities(version_tags);

  // generate the header
  const date = now.toISOString().substr(0, 10);
  let header = `generated ${date}, Mozilla Guideline v${guideline}, ${version_tags}`;
  header += configs[server].supportsHsts !== false && hsts ? ', HSTS' : '';
  header += supportsOcspStapling && ocsp ? ', OCSP' : '';

  const link = `${origin}${pathname}#${fragment}`;

  // we need to remove TLS 1.3 from the supported protocols if the software is too old
  let protocols = ssc.tls_versions;
  if (!configs[server].tls13
      || !minver(configs[server].tls13, serverVersion)
      || !minver(configs['openssl'].tls13, opensslVersion)) {
    protocols = protocols.filter(p => p !== 'TLSv1.3');
  }

  const cipherFormat = configs[server].cipherFormat ? configs[server].cipherFormat : 'openssl';
  let ciphers = cipherFormat === 'go' ? ssc.ciphers['iana'] : ssc.ciphers[cipherFormat];
  const supportedCiphers = configs[server].supportedCiphers
    ? configs[server].supportedCiphers
    : cipherFormat === 'go' ? configs['go'].supportedCiphers : null;
  if (supportedCiphers) {
    ciphers = ciphers.filter(suite => supportedCiphers.indexOf(suite) !== -1);
  } else {
    // make a defensive copy so callers can't mutate the guideline data
    ciphers = ciphers.slice();
  }
  if (ciphers.length && ciphers[0] === '@SECLEVEL=0') ciphers.shift();
  if (configs[server].usesOpenssl !== false && minver('3.0.0', opensslVersion)) {
    if (protocols.includes('TLSv1.1')) ciphers.unshift('@SECLEVEL=0');
  }

  // PQ-only mode requires TLS 1.3 (key_share extension); see state.js comment.
  if (pqEffective === 'only') {
    protocols = ['TLSv1.3'];
  }

  // Apply PQ mode to tls_curves (groups).
  let tlsCurves = (ssc.tls_curves || []).slice();
  if (pqEffective === 'none') {
    tlsCurves = tlsCurves.filter(g => !isPqGroup(g));
  } else if (pqEffective === 'only') {
    tlsCurves = tlsCurves.filter(g => isPqGroup(g));
    if (tlsCurves.length === 0) {
      tlsCurves = ['X25519MLKEM768'];
    }
  }

  return {
    form: {
      config,
      hsts: !!hsts && configs[server].supportsHsts !== false,
      ocsp: !!ocsp && !!supportsOcspStapling,
      opensslVersion,
      pq: pqEffective,
      server,
      serverName: configs[server].name,
      serverVersion,
      version_tags,
    },
    output: {
      ciphers,
      cipherSuites: ssc.ciphersuites,
      date,
      dhCommand: `curl ${origin}/ffdhe${ssc.dh_param_size}.txt`,
      dhParamSize: ssc.dh_param_size,
      fragment,
      hasVersions: configs[server].hasVersions !== false,
      header,
      hstsMaxAge: ssc.hsts_min_age,
      hstsRedirectCode: 308,
      latestVersion: configs[server].latestVersion,
      link,
      oldestClients: ssc.oldest_clients,
      origin,
      protocols,
      pqMode: pqEffective,
      serverPreferredOrder: ssc.server_preferred_order,
      showSupports: configs[server].showSupports !== false,
      supportsHsts: configs[server].supportsHsts !== false,
      supportsOcspStapling: !!supportsOcspStapling,
      supportsCipherSelection: configs[server].supportsCipherSelection !== false,
      supportsCurveSelection: configs[server].supportsCurveSelection !== false,
      supportsPq: !!configs[server].supportsPq,
      tlsCurves,
      usesDhe: ciphers.join(':').includes(':DHE') || ciphers.join(':').includes('_DHE_'),
      usesOpenssl: configs[server].usesOpenssl !== false,
    },
  };
}
