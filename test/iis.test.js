// IIS / Schannel PowerShell helper — generic-suite tests via the shared harness
// plus IIS-specific assertions for the backup / -Restore code path.
import { runStandardHelperSuite } from './_helpers/harness.js';
import iis from '../src/js/helpers/iis.js';

runStandardHelperSuite({
  name: 'iis',
  helper: iis,
  serverVersion: '10.0.26100',
  cipherFormat: 'iana',
  supportsHsts: true,
  supportsPq: true,
  protocolDirective: {
    modern:       /\$EnabledProtocols\s*=\s*@\('TLS 1\.3'\)/,
    intermediate: /\$EnabledProtocols\s*=\s*@\('TLS 1\.2',\s*'TLS 1\.3'\)/,
    old:          /\$EnabledProtocols\s*=\s*@\('TLS 1\.0',\s*'TLS 1\.1',\s*'TLS 1\.2',\s*'TLS 1\.3'\)/,
  },
  versionTokens: {
    'TLSv1':   /'TLS 1\.0'/,
    'TLSv1.1': /'TLS 1\.1'/,
    'TLSv1.2': /'TLS 1\.2'/,
    'TLSv1.3': /'TLS 1\.3'/,
  },
  hstsHeader: /Strict-Transport-Security:\s*max-age=63072000;\s*includeSubDomains/,
  extraTests: (t) => {
    t('emits a -Restore param block and reg.exe export of the SCHANNEL backup', async () => {
      const { default: iisH } = await import('../src/js/helpers/iis.js');
      const { makeForm, makeOutput } = await import('./_helpers/fixtures.js');
      const { default: assert } = await import('node:assert/strict');
      const out = iisH(
        makeForm({ serverVersion: '10.0.26100', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // -Restore CLI switch is documented + parameterised
      assert.match(out, /\.\\Set-IISTls\.ps1\s+-Restore/);
      assert.match(out, /\[switch\]\$Restore/);
      assert.match(out, /\[string\]\$BackupPath/);
      assert.match(out, /if \(\$Restore\)/);
      // backup is written via reg.exe export against the SCHANNEL key
      assert.match(out, /reg\.exe.+export.+SCHANNEL/);
      // restore re-imports the backup
      assert.match(out, /reg\.exe.+import/);
      // requires elevation
      assert.match(out, /Administrator/);
    });

    t('PQ-only mode emits the X25519MLKEM768 / Schannel MLKEM768X25519 hybrid group', async () => {
      const { default: iisH } = await import('../src/js/helpers/iis.js');
      const { makeForm, makeOutput } = await import('./_helpers/fixtures.js');
      const { default: assert } = await import('node:assert/strict');
      const out = iisH(
        makeForm({ serverVersion: '10.0.26100', config: 'modern', pq: 'only' }),
        makeOutput('modern', {
          cipherFormat: 'iana',
          pqMode: 'only',
          supportsPq: true,
          tlsCurves: ['X25519MLKEM768'],
        }),
      );
      assert.match(out, /MLKEM768X25519/);
      assert.match(out, /X25519MLKEM768/);
      assert.match(out, /post[- ]?quantum|ML[- ]?KEM|\bPQ\b/i);
    });

    t('HSTS write targets the IIS 10 native <hsts> element with the expected max-age', async () => {
      const { default: iisH } = await import('../src/js/helpers/iis.js');
      const { makeForm, makeOutput } = await import('./_helpers/fixtures.js');
      const { default: assert } = await import('node:assert/strict');
      const out = iisH(
        makeForm({ serverVersion: '10.0.26100', hsts: true }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      assert.match(out, /\$hstsFilter\s*=\s*"system\.applicationHost\/sites\/site\[@name='\$siteName'\]\/hsts"/);
      assert.match(out, /Set-WebConfigurationProperty.+-Filter \$hstsFilter/);
      assert.match(out, /-Name 'max-age'\s+-Value 63072000/);
      assert.match(out, /-Name 'includeSubDomains'\s+-Value \$true/);
    });
  },
});
