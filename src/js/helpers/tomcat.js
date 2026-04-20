export default (form, output) => {
 var conf =
      '<!--\n'+
      output.header+'\n'+
      output.link+'\n'+
      '-->\n';

 if (form.hsts) {
    conf +=
      '<Connector\n'+
      '    port="80"\n'+
      '    redirectPort="443" />\n'+
      '\n'+
      '<!--\n'+
      '  HTTP Strict Transport Security (HSTS) is emitted by Tomcat\'s built-in\n'+
      '  HttpHeaderSecurityFilter (Tomcat 8.5+). Add the snippet below to\n'+
      '  WEB-INF/web.xml of your application (or to $CATALINA_BASE/conf/web.xml\n'+
      '  to apply it to every deployed app). See:\n'+
      '    https://tomcat.apache.org/tomcat-'+(form.serverVersion || '11').split('.')[0]+'.0-doc/config/filter.html#HTTP_Header_Security_Filter\n'+
      '\n'+
      '  <filter>\n'+
      '    <filter-name>httpHeaderSecurity</filter-name>\n'+
      '    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>\n'+
      '    <async-supported>true</async-supported>\n'+
      '    <init-param>\n'+
      '      <param-name>hstsEnabled</param-name>\n'+
      '      <param-value>true</param-value>\n'+
      '    </init-param>\n'+
      '    <init-param>\n'+
      '      <param-name>hstsMaxAgeSeconds</param-name>\n'+
      '      <param-value>'+output.hstsMaxAge+'</param-value>\n'+
      '    </init-param>\n'+
      '    <init-param>\n'+
      '      <param-name>hstsIncludeSubDomains</param-name>\n'+
      '      <param-value>true</param-value>\n'+
      '    </init-param>\n'+
      '  </filter>\n'+
      '  <filter-mapping>\n'+
      '    <filter-name>httpHeaderSecurity</filter-name>\n'+
      '    <url-pattern>/*</url-pattern>\n'+
      '    <dispatcher>REQUEST</dispatcher>\n'+
      '  </filter-mapping>\n'+
      '\n'+
      '  Equivalent rendered response header:\n'+
      '    Strict-Transport-Security: max-age='+output.hstsMaxAge+'; includeSubDomains\n'+
      '-->\n'+
      '\n';
 }

    conf +=
      '<Connector\n'+
      '    port="443"\n'+
      '    SSLEnabled="true">\n'+
      '\n'+
           (output.protocols.includes("TLSv1.3") ? '    <!-- TLSv1.3 requires Java 11 or higher -->\n' : '')+
      '    <SSLHostConfig\n';

 if (output.ciphers.length) {
    conf +=
      '        ciphers="'+
        (output.protocols.includes("TLSv1.3") ? output.cipherSuites.join(':')+':' : '')+
        output.ciphers.join(':')+'"\n';
 }

    conf +=
      '        disableSessionTickets="true"\n'+
      '        honorCipherOrder="'+(output.serverPreferredOrder ? 'true' : 'false')+'"\n'+
      '        protocols="'+output.protocols.join(',')+'">\n'+
      '\n'+
      '        <Certificate\n'+
      '            certificateFile="/path/to/signed_certificate"\n'+
      '            certificateChainFile="/path/to/intermediate_certificate"\n'+
      '            certificateKeyFile="/path/to/private_key" />\n'+
      '    </SSLHostConfig>\n'+
      '\n'+
      '    <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />\n'+
      '</Connector>\n';

  return conf;
};
