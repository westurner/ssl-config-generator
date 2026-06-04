// Shared "PQ via openssl.cnf" cross-reference comment block.
//
// Helpers whose configs.js entry sets pqViaOpensslCnf:true (libssl-linked
// servers with no native group / curve directive — see configs.js header)
// call this when form.pq !== 'none' to surface a short, hash-prefixed
// comment that points the operator at the openssl.cnf escape hatch and
// at the OPENSSL_CONF environment variable. Centralised so all six
// pqViaOpensslCnf:true helpers (coturn, litespeed, mysql, openlitespeed,
// redis, squid) emit the same wording — a future text update lands in
// one place.
//
// Returns '' when the operator did not request PQ (form.pq === 'none')
// or when the helper has not opted in to the flag, so callers can
// unconditionally splice the result into their config string.
export default function pqOpensslCnfNote(form, output) {
  if (!output.pqViaOpensslCnf) return '';
  if (!form.pq || form.pq === 'none') return '';
  return '\n'+
    '# Post-quantum (ML-KEM hybrid) key exchange:\n'+
    '#   This server has no native TLS group / curve directive; ML-KEM\n'+
    '#   hybrid groups (e.g. X25519MLKEM768) reach the wire only if the\n'+
    '#   linked OpenSSL is configured to offer them via openssl.cnf, in\n'+
    '#   the [system_default_sect] Groups = … line. See the\n'+
    '#   "OpenSSL (openssl.cnf)" target in this generator for a\n'+
    '#   ready-to-paste snippet, and locate your active openssl.cnf with:\n'+
    '#       openssl version -d\n'+
    '#   To use a different openssl.cnf for THIS process only (e.g. when\n'+
    '#   you do not want to change the system-wide file), set the\n'+
    '#   OPENSSL_CONF environment variable before launching the server:\n'+
    '#       OPENSSL_CONF=/path/to/your-openssl.cnf <server-binary> ...\n'+
    '#   The OPENSSL_CONF override has been honoured by libssl since\n'+
    '#   OpenSSL 0.9.7 (see openssl-config(5) / OPENSSL_init_crypto(3)).\n';
}
