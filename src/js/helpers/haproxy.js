import minver from './minver.js';

export default (form, output) => {
 // Only version 1.5.0 and newer support TLS
 if (!minver("1.5.0", form.serverVersion)) {
    return 'Sorry, TLS is not supported in this version of HAProxy.\n';
 }

 function haproxy_ssl_default_opts (tag) {
   var conf =
      (minver("2.9.0", form.serverVersion) || tag === 'bind'
        ?
      '    ssl-default-'+tag+'-curves '+output.tlsCurves.join(':')+'\n'
        : '')+
      (output.ciphers.length
        ?
      '    ssl-default-'+tag+'-ciphers '+output.ciphers.join(':')+'\n'
        : '')+
      (minver("1.9.0", form.serverVersion) && minver("1.1.1", form.opensslVersion)
        ?
      '    ssl-default-'+tag+'-ciphersuites '+output.cipherSuites.join(':')+'\n'
        : '')+
      '    ssl-default-'+tag+'-options'+
      (minver("1.8.0", form.serverVersion) && !output.serverPreferredOrder && tag === 'bind'
        ? ' prefer-client-ciphers'
        : '')+
      (minver("2.2.0", form.serverVersion)
        ? ' ssl-min-ver '+(output.protocols[0] == 'TLSv1' ? 'TLSv1.0' : output.protocols[0])
        : (!output.protocols.includes('SSLv3')   ? ' no-sslv3'  : '')+
          (!output.protocols.includes('TLSv1')   ? ' no-tlsv10' : '')+
          (!output.protocols.includes('TLSv1.1') ? ' no-tlsv11' : '')+
          (!output.protocols.includes('TLSv1.2') ? ' no-tlsv12' : ''))+
      ' no-tls-tickets\n'+
      '\n';
    return conf;
 }

 var conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      'global\n'+
      '    # '+form.config+' configuration\n';

 // Post-quantum hybrid groups (X25519MLKEM768, SecP256r1MLKEM768,
 // SecP384r1MLKEM1024) are passed through to OpenSSL via
 // ssl-default-bind-curves / ssl-default-server-curves (HAProxy 2.9+).
 // Surface dependencies so an operator who selects PQ on an older build
 // does not silently lose it:
 //   - HAProxy < 2.9 has no `ssl-default-bind-curves` directive at all,
 //     so the per-bind `curves` keyword is the only way to set them.
 //   - OpenSSL < 3.5 doesn't recognise the ML-KEM names natively; the
 //     oqs-provider from liboqs must be loaded via openssl.cnf.
 if (form.pq && form.pq !== 'none') {
   if (!minver("2.9.0", form.serverVersion)) {
     conf +=
       '    # WARNING: HAProxy < 2.9 has no ssl-default-bind-curves\n'+
       '    #          directive; ML-KEM hybrid groups must be set per-bind\n'+
       '    #          via the `curves` keyword on each `bind` line, e.g.\n'+
       '    #          bind :443 ssl crt /path/to/cert.pem curves '+(output.tlsCurves || []).join(':')+'\n';
   }
   if (!minver("3.5.0", form.opensslVersion)) {
     conf +=
       '    # WARNING: built-in ML-KEM hybrid groups (X25519MLKEM768,\n'+
       '    #          SecP256r1MLKEM768, SecP384r1MLKEM1024) require the\n'+
       '    #          linked OpenSSL to be 3.5.0 or newer. Earlier OpenSSL\n'+
       '    #          needs the "oqs-provider" from liboqs (loaded via\n'+
       '    #          openssl.cnf) to expose these groups.\n';
   }
 }

 conf +=
      haproxy_ssl_default_opts('bind')+
      haproxy_ssl_default_opts('server');

 if (output.usesDhe) {
    var ssl_security_level = '';
    if (output.protocols.includes("TLSv1.1")
        && minver("3.0.0", form.opensslVersion)
        && minver("3.0.0", form.serverVersion)) {
      ssl_security_level =
      '    ssl-security-level 0\n';
    }
    conf +=
      minver("1.6.0", form.serverVersion)
        ?
      '    # '+output.dhCommand+' > /path/to/dhparam\n'+
           ssl_security_level+
      '    ssl-dh-param-file /path/to/dhparam\n\n'
        :
      '    tune.ssl.default-dh-param 2048\n\n';
 }

    conf +=
      'frontend ft_test\n'+
      '    mode    http\n'+
      '    bind    :443 ssl crt /path/to/<cert+privkey+intermediate>'+(minver("1.8.0", form.serverVersion) ? ' alpn h2,http/1.1' : '')+'\n'+
      '    bind    :80\n';

 // OCSP stapling is wired through an out-of-band file: HAProxy 1.6+
 // automatically loads <crt>.ocsp (DER-encoded OCSP response) when it
 // sits next to the certificate referenced above. 1.7+ allows refresh
 // via `set ssl ocsp-response` over the stats / admin socket; 2.8+ ships
 // `tune.ssl.ocsp-update.mode on` for an in-process auto-updater.
 // See: https://docs.haproxy.org/2.8/configuration.html#5.1
 if (form.ocsp) {
   conf +=
      '\n'+
      '    # OCSP stapling: place a DER-encoded OCSP response next to the\n'+
      '    # certificate as <crt>.ocsp; HAProxy '+(minver("1.6.0", form.serverVersion) ? form.serverVersion : '1.6+')+' loads it at startup.\n'+
      '    #   openssl ocsp -no_nonce -respout /path/to/<cert>.ocsp \\\n'+
      '    #     -issuer /path/to/intermediate.pem \\\n'+
      '    #     -cert   /path/to/<cert+privkey+intermediate> \\\n'+
      '    #     -url    "$(openssl x509 -in /path/to/<cert+privkey+intermediate> -noout -ocsp_uri)"\n';
   if (minver("2.8.0", form.serverVersion)) {
     conf +=
      '    # HAProxy 2.8+ can auto-refresh stapled responses in-process:\n'+
      '    #   tune.ssl.ocsp-update.mode on   # add to the global section above\n';
   }
   else if (minver("1.7.0", form.serverVersion)) {
     conf +=
      '    # Refresh at runtime over the admin socket (HAProxy 1.7+):\n'+
      '    #   echo "set ssl ocsp-response $(base64 -w0 /path/to/<cert>.ocsp)" \\\n'+
      '    #     | socat stdio /var/run/haproxy.sock\n';
   }
   else {
     conf +=
      '    # HAProxy '+form.serverVersion+' has no runtime-refresh command;\n'+
      '    # reload HAProxy after rewriting the .ocsp file to pick up changes.\n';
   }
 }

 if (form.hsts) {
    conf +=
      '    redirect scheme https code '+output.hstsRedirectCode+' if !{ ssl_fc }\n'+
      '\n'+
      '    # HSTS ('+output.hstsMaxAge+' seconds)\n'+
      '    http-response set-header Strict-Transport-Security "max-age='+output.hstsMaxAge+'; includeSubDomains"\n';
 }

  return conf;
};
