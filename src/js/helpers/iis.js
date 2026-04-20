// IIS / Windows Schannel TLS configuration template.
//
// IIS itself doesn't have a per-site cipher / protocol knob — it inherits
// everything from the host's Schannel SSP (the same TLS stack used by every
// .NET / WinHTTP / RDP / SMB consumer on the box). This helper therefore
// emits a self-contained PowerShell script that:
//
//   1. Backs up the existing SCHANNEL state to a `.reg` file
//      (HKLM\SYSTEM\…\SCHANNEL plus the cipher-suite policy key
//      HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002)
//      via `reg.exe export`, so the operator always has a one-shot rollback.
//   2. Sets the registry values for the Mozilla profile: enabled-protocol
//      `Server`/`Client` keys, `Functions` (cipher-suite order, IANA names),
//      `EccCurves` (TLS named-group order, Schannel names), and HSTS via
//      `Set-WebConfigurationProperty` when form.hsts.
//   3. Supports a `-Restore` switch that re-imports the .reg backup so the
//      operator can revert without hand-editing anything.
//
// References (see src/static/citations.bib):
//   - HKLM\…\SCHANNEL\Protocols layout:                  ms-manage-tls
//   - Per-value Schannel registry knobs:                 ms-tls-registry
//   - Cipher-suite ordering ("Functions" REG_SZ):        ms-cipher-suite-order
//   - Schannel cipher-suite implementation status:       ms-tls-cipher-suites
//   - TLS 1.3 in Schannel (Server 2022+):                ms-tls13-schannel
//   - HSTS in IIS 10 v1709+:                             ms-iis10-hsts
//   - Hybrid PQ (ML-KEM) in Schannel / SymCrypt:         ms-pqc-windows-insider, ms-symcrypt-mlkem
//   - Mozilla Server Side TLS guideline:                 mozilla-server-side-tls
//   - ML-KEM specification:                              nist-fips-203
//   - Hybrid ECDHE-MLKEM TLS NamedGroup codepoints:      ietf-tls-mlkem
//
// Schannel group / curve naming (mapped from the Mozilla guideline names):
//   X25519           -> curve25519
//   prime256v1       -> NistP256
//   secp384r1        -> NistP384
//   secp521r1        -> NistP521
//   X25519MLKEM768   -> MLKEM768X25519   (hybrid PQ, Server 2025 / Win 11 24H2+)

const SCHANNEL_GROUP_MAP = {
  'X25519':            'curve25519',
  'prime256v1':        'NistP256',
  'secp384r1':         'NistP384',
  'secp521r1':         'NistP521',
  'X25519MLKEM768':    'MLKEM768X25519',
  'SecP256r1MLKEM768': 'MLKEM768P256',
  'SecP384r1MLKEM1024':'MLKEM1024P384',
};

// Mozilla guideline TLS-version tokens -> Schannel registry subkey names.
const SCHANNEL_PROTOCOL_MAP = {
  'TLSv1':   'TLS 1.0',
  'TLSv1.1': 'TLS 1.1',
  'TLSv1.2': 'TLS 1.2',
  'TLSv1.3': 'TLS 1.3',
};

export default (form, output) => {
  // Defensive input check — Schannel registry edits are global, so we'd
  // rather fail loudly than splice an `undefined` into a HKLM\… path.
  if (!output || !Array.isArray(output.protocols) || !Array.isArray(output.ciphers) || !Array.isArray(output.tlsCurves)) {
    throw new Error('iis: output.protocols / output.ciphers / output.tlsCurves are required');
  }

  const enabledProtocols = output.protocols
    .map(p => SCHANNEL_PROTOCOL_MAP[p])
    .filter(Boolean);

  const eccCurves = [];
  const groupNotes = [];
  output.tlsCurves.forEach(g => {
    const mapped = SCHANNEL_GROUP_MAP[g];
    if (mapped) {
      if (!eccCurves.includes(mapped)) eccCurves.push(mapped);
      groupNotes.push(g + ' -> ' + mapped);
    }
    else {
      groupNotes.push(g + ' (no Schannel mapping; left for OS defaults)');
    }
  });

  const psQuoteList = (arr) => arr.map(x => "'" + x + "'").join(', ');

  let conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      '#\n'+
      '# Save this file as Set-IISTls.ps1 and run it from an ELEVATED PowerShell\n'+
      '# prompt (Run as Administrator). The script edits Schannel registry keys\n'+
      '# that are read by every TLS consumer on the box (IIS, .NET, WinHTTP,\n'+
      '# RDP, SMB, ...), so the changes apply system-wide.\n'+
      '#\n'+
      '# Usage:\n'+
      '#   .\\Set-IISTls.ps1                          # back up current SCHANNEL state, then apply\n'+
      '#   .\\Set-IISTls.ps1 -BackupPath C:\\tls.reg    # custom backup path\n'+
      '#   .\\Set-IISTls.ps1 -Restore -BackupPath C:\\tls.reg   # roll back to that .reg file\n'+
      '#\n'+
      '# Schannel protocol / cipher / group changes require a REBOOT to take effect.\n'+
      '#\n'+
      '# Mozilla profile groups -> Schannel names:\n';
  groupNotes.forEach(n => { conf += '#   '+n+'\n'; });

  if (form && form.pq === 'only') {
    conf +=
      '#\n'+
      '# PQ-only mode: this profile pins the X25519MLKEM768 hybrid post-quantum\n'+
      '# key-exchange group (Schannel name MLKEM768X25519). Hybrid ML-KEM is\n'+
      '# available on Windows Server 2025 / Windows 11 24H2 (and later Insider\n'+
      '# builds). On older Windows the EccCurves value will simply be ignored\n'+
      '# and Schannel will fall back to its defaults.\n';
  }

  conf +=
      '\n'+
      '[CmdletBinding()]\n'+
      'param(\n'+
      '    [switch]$Restore,\n'+
      '    [string]$BackupPath = (Join-Path $env:USERPROFILE ("schannel-backup-{0}.reg" -f (Get-Date -Format \'yyyyMMdd-HHmmss\')))\n'+
      ')\n'+
      '\n'+
      '$ErrorActionPreference = \'Stop\'\n'+
      '\n'+
      '# Require Administrator: every key written below lives under HKLM.\n'+
      '$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()\n'+
      '$principal = New-Object Security.Principal.WindowsPrincipal $identity\n'+
      'if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n'+
      '    throw \'Set-IISTls.ps1 must be run from an elevated PowerShell prompt (Administrator).\'\n'+
      '}\n'+
      '\n'+
      '$SchannelKey = \'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\'\n'+
      '$CipherKey   = \'HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\'\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# -Restore: re-import the .reg backup file and exit. The operator MUST pass\n'+
      '# the same -BackupPath that was printed at the end of the original run.\n'+
      '# ---------------------------------------------------------------------------\n'+
      'if ($Restore) {\n'+
      '    if (-not (Test-Path -LiteralPath $BackupPath)) {\n'+
      '        throw "Backup file not found: $BackupPath"\n'+
      '    }\n'+
      '    Write-Host "Restoring SCHANNEL settings from $BackupPath ..."\n'+
      '    $rc = (Start-Process -FilePath reg.exe -ArgumentList @(\'import\', $BackupPath) -Wait -PassThru -NoNewWindow).ExitCode\n'+
      '    if ($rc -ne 0) { throw "reg.exe import failed (exit $rc)" }\n'+
      '    $cipherBackup = $BackupPath + \'.cipher.reg\'\n'+
      '    if (Test-Path -LiteralPath $cipherBackup) {\n'+
      '        Write-Host "Restoring cipher policy from $cipherBackup ..."\n'+
      '        $rc = (Start-Process -FilePath reg.exe -ArgumentList @(\'import\', $cipherBackup) -Wait -PassThru -NoNewWindow).ExitCode\n'+
      '        if ($rc -ne 0) { throw "reg.exe import failed for cipher policy (exit $rc)" }\n'+
      '    }\n'+
      '    Write-Host \'A reboot is required for Schannel changes to take effect.\'\n'+
      '    return\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# 1. Back up current SCHANNEL + cipher-policy keys to a .reg file.\n'+
      '#    The cipher-policy key may not exist on a fresh install; we ignore that.\n'+
      '# ---------------------------------------------------------------------------\n'+
      'Write-Host "Backing up $SchannelKey -> $BackupPath ..."\n'+
      '$rc = (Start-Process -FilePath reg.exe -ArgumentList @(\'export\', $SchannelKey, $BackupPath, \'/y\') -Wait -PassThru -NoNewWindow).ExitCode\n'+
      'if ($rc -ne 0) { throw "reg.exe export failed for SCHANNEL key (exit $rc)" }\n'+
      '\n'+
      '$cipherBackup = $BackupPath + \'.cipher.reg\'\n'+
      'if (Test-Path -LiteralPath ("Registry::" + $CipherKey)) {\n'+
      '    Write-Host "Backing up $CipherKey -> $cipherBackup ..."\n'+
      '    Start-Process -FilePath reg.exe -ArgumentList @(\'export\', $CipherKey, $cipherBackup, \'/y\') -Wait -NoNewWindow | Out-Null\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# 2. Enable the Mozilla '+(form && form.config ? form.config : 'intermediate')+' protocol set.\n'+
      '# ---------------------------------------------------------------------------\n'+
      '$EnabledProtocols = @('+psQuoteList(enabledProtocols)+')\n'+
      'foreach ($p in $EnabledProtocols) {\n'+
      '    foreach ($side in \'Server\',\'Client\') {\n'+
      '        $k = "Registry::$SchannelKey\\Protocols\\$p\\$side"\n'+
      '        New-Item -Path $k -Force | Out-Null\n'+
      '        New-ItemProperty -Path $k -Name \'Enabled\'           -Value 0xFFFFFFFF -PropertyType DWord -Force | Out-Null\n'+
      '        New-ItemProperty -Path $k -Name \'DisabledByDefault\' -Value 0          -PropertyType DWord -Force | Out-Null\n'+
      '    }\n'+
      '}\n'+
      '# Note: protocols not listed above are left at their Schannel defaults.\n'+
      '# To explicitly disable a legacy protocol, set Enabled=0 / DisabledByDefault=1\n'+
      '# under the corresponding HKLM\\...\\SCHANNEL\\Protocols\\<name>\\Server key.\n'+
      '\n';

  // -- 3. Cipher-suite ordering ---------------------------------------------
  if (output.ciphers.length) {
    conf +=
      '# ---------------------------------------------------------------------------\n'+
      '# 3. Cipher-suite preference order (IANA names, comma-separated).\n'+
      '#    Written as the REG_SZ "Functions" value under the Group Policy\n'+
      '#    cipher-policy key; Schannel reads it on next handshake.\n'+
      '# ---------------------------------------------------------------------------\n'+
      '$CipherSuites = @(\n';
    output.ciphers.forEach((c, i) => {
      conf += '    \''+c+'\''+(i < output.ciphers.length - 1 ? ',' : '')+'\n';
    });
    conf +=
      ')\n'+
      'New-Item -Path "Registry::$CipherKey" -Force | Out-Null\n'+
      'New-ItemProperty -Path "Registry::$CipherKey" -Name \'Functions\' -Value ($CipherSuites -join \',\') -PropertyType String -Force | Out-Null\n'+
      '\n';
  }

  // -- 4. ECC / named-group ordering ----------------------------------------
  if (eccCurves.length) {
    conf +=
      '# ---------------------------------------------------------------------------\n'+
      '# 4. TLS named-group / curve preference (Schannel "EccCurves" REG_MULTI_SZ).\n'+
      '# ---------------------------------------------------------------------------\n'+
      '$EccCurves = @('+psQuoteList(eccCurves)+')\n'+
      'New-Item -Path "Registry::$CipherKey" -Force | Out-Null\n'+
      'New-ItemProperty -Path "Registry::$CipherKey" -Name \'EccCurves\' -Value $EccCurves -PropertyType MultiString -Force | Out-Null\n'+
      '\n';
  }

  // -- 5. HSTS ---------------------------------------------------------------
  if (form && form.hsts) {
    conf +=
      '# ---------------------------------------------------------------------------\n'+
      '# 5. HSTS (IIS 10 v1709+: native <hsts> element under <site>).\n'+
      '#    Adjust the site name if you are not configuring "Default Web Site".\n'+
      '# ---------------------------------------------------------------------------\n'+
      'Import-Module WebAdministration -ErrorAction SilentlyContinue\n'+
      '$siteName = \'Default Web Site\'\n'+
      '$hstsFilter = "system.applicationHost/sites/site[@name=\'$siteName\']/hsts"\n'+
      'Set-WebConfigurationProperty -PSPath \'MACHINE/WEBROOT/APPHOST\' -Filter $hstsFilter -Name \'enabled\'             -Value $true\n'+
      'Set-WebConfigurationProperty -PSPath \'MACHINE/WEBROOT/APPHOST\' -Filter $hstsFilter -Name \'max-age\'             -Value '+output.hstsMaxAge+'\n'+
      'Set-WebConfigurationProperty -PSPath \'MACHINE/WEBROOT/APPHOST\' -Filter $hstsFilter -Name \'includeSubDomains\'   -Value $true\n'+
      'Set-WebConfigurationProperty -PSPath \'MACHINE/WEBROOT/APPHOST\' -Filter $hstsFilter -Name \'redirectHttpToHttps\' -Value $true\n'+
      '# Strict-Transport-Security: max-age='+output.hstsMaxAge+'; includeSubDomains\n'+
      '\n';
  }

  conf +=
      'Write-Host \'\'\n'+
      'Write-Host \'Done. A REBOOT is required for Schannel protocol/cipher/group changes to take effect.\'\n'+
      'Write-Host "To revert, run:  .\\Set-IISTls.ps1 -Restore -BackupPath \'$BackupPath\'"\n';

  return conf;
};
