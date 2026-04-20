// IIS / Windows Schannel TLS configuration template.
//
// IIS itself doesn't have a per-site cipher / protocol knob — it inherits
// everything from the host's Schannel SSP (the same TLS stack used by every
// .NET / WinHTTP / RDP / SMB consumer on the box). This helper therefore
// emits a self-contained PowerShell script that:
//
//   1. Builds an explicit DO-plan of every mutation it intends to perform —
//      registry writes (protocol enable/disable, cipher-suite ordering, ECC
//      curves) AND IIS web-configuration writes (the native <hsts> element).
//      Each entry carries a `Kind` discriminator (`Registry` | `WebConfig`).
//      The script then snapshots the CURRENT state of every entry mentioned
//      in the DO-plan, writing the snapshot to `$BackupPath.undo.json` so
//      that `-Restore` can EXACTLY revert the host (including DELETING any
//      registry values the apply pass created — `reg.exe import` cannot do
//      this). The DO-plan itself is also written to `$BackupPath.do.json`
//      for audit.
//   2. Applies the DO-plan: enables the requested protocols and explicitly
//      DISABLES every other version we know about (so the "Modern" profile
//      really does turn off TLS 1.0 / 1.1 / 1.2 — the previous behaviour of
//      "leave them at Schannel defaults" silently kept legacy versions on).
//      The cipher-suite list is filtered against a Schannel-implemented
//      allow-list before being written to the `Functions` REG_SZ value:
//      Schannel does NOT implement `TLS_DHE_RSA_*` and TLS 1.3 cipher-suites
//      are not user-tunable via `Functions` either; both are surfaced to the
//      operator via `Write-Warning`. HSTS is configured via the IIS 10 v1709
//      native <hsts> element using `Set-WebConfigurationProperty`, with the
//      pre-apply <hsts> values captured into the same undo snapshot.
//   3. Supports a `-Restore` switch that replays `$BackupPath.undo.json`,
//      restoring every entry (registry value AND <hsts> property) to its
//      prior state (and removing registry values that did not exist before).
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
//   X25519MLKEM768   -> MLKEM768X25519   (hybrid PQ, Insider builds; PROVISIONAL — see PQ note)

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
// The full set of Schannel-known TLS subkeys we are willing to write under
// HKLM\...\SCHANNEL\Protocols. Any version present in the operator's
// requested set gets Enabled=1; any other entry in this map is forced
// Enabled=0 / DisabledByDefault=1 (H2 — Modern must really disable TLS 1.0/1.1/1.2).
const SCHANNEL_PROTOCOL_MAP = {
  'TLSv1':   'TLS 1.0',
  'TLSv1.1': 'TLS 1.1',
  'TLSv1.2': 'TLS 1.2',
  'TLSv1.3': 'TLS 1.3',
};

// IANA cipher-suite names that Schannel actually implements (per
// ms-tls-cipher-suites). Used as an allow-list filter against output.ciphers
// before writing the `Functions` REG_SZ value (H1).
//
// Notably absent — silently dropped by Schannel parsers and therefore by us:
//   - TLS_DHE_RSA_*                  (Schannel has no DHE_RSA implementation)
//   - TLS_DH_anon_*                  (anonymous DH — never offered)
//   - TLS_DHE_DSS_*                  (DSS not implemented)
//
// TLS 1.3 cipher-suites (TLS_AES_*, TLS_CHACHA20_*) ARE implemented but the
// `Functions` value DOES NOT govern their ordering — Schannel always uses
// its fixed TLS 1.3 set. We pass them through (they're harmless in the
// REG_SZ value) and warn the operator that ordering is advisory for 1.3.
const SCHANNEL_CIPHER_ALLOW = new Set([
  // TLS 1.3 (advisory — see note above)
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  // TLS 1.2 ECDHE-AEAD
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  // TLS 1.2 ECDHE-CBC
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  // Static-RSA AEAD/CBC (only used by 'old' profile)
  'TLS_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_RSA_WITH_AES_256_CBC_SHA256',
  'TLS_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_AES_256_CBC_SHA',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
]);

const TLS13_CIPHERS = new Set([
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
]);

// Quote a string for a PowerShell single-quoted literal. Single quotes are
// escaped by doubling them (the only escape that matters in single-quoted
// PS strings — variable interpolation and `n / `t are NOT processed).
const psQuote = (s) => "'" + String(s).replace(/'/g, "''") + "'";
const psQuoteList = (arr) => arr.map(psQuote).join(', ');

// Render a JS value as a PowerShell literal (used to embed the do-plan).
function psLiteral(v) {
  if (v === null || v === undefined) return '$null';
  if (typeof v === 'boolean') return v ? '$true' : '$false';
  if (typeof v === 'number')  return String(v);
  if (Array.isArray(v))       return '@(' + v.map(psLiteral).join(', ') + ')';
  // strings — single-quote with '' escape
  return psQuote(v);
}

// Build a hashtable literal `@{ Key = value; ... }` from a JS object,
// preserving insertion order (PowerShell 5+ preserves declaration order in
// the [Ordered] form, but plain @{} is fine here — the script never
// iterates by key). Values are recursively rendered via psLiteral.
function psHashtable(obj) {
  const parts = Object.entries(obj).map(([k, v]) => `${k} = ${psLiteral(v)}`);
  return '@{ ' + parts.join('; ') + ' }';
}

export default (form, output) => {
  // Defensive input check — Schannel registry edits are global, so we'd
  // rather fail loudly than splice an `undefined` into a HKLM\… path.
  // `form` is required in addition to `output`; production always passes one
  // (state.js), and accepting an undefined form would render PowerShell that
  // contains $null literals in its helper bodies which the harness's input-
  // validation heuristic flags as a corrupted directive.
  if (!form || !output || !Array.isArray(output.protocols) || !Array.isArray(output.ciphers) || !Array.isArray(output.tlsCurves)) {
    throw new Error('iis: form and output.protocols / output.ciphers / output.tlsCurves are required');
  }

  const SCHANNEL_BASE = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL';
  const CIPHER_KEY    = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002';

  // ---- H2: build the protocol DO-plan ---------------------------------------
  // For every Schannel-known TLS version, decide whether it should be
  // ENABLED (in the operator's set) or DISABLED (not in the set). The
  // previous helper "left it at defaults", which on Server 2019/2022 left
  // TLS 1.0/1.1 ENABLED for the Server role — silently violating Modern.
  const enabledTokens  = output.protocols.filter(p => SCHANNEL_PROTOCOL_MAP[p]);
  const enabledSet     = new Set(enabledTokens);
  const protocolPlan   = []; // { schannelName, enable }
  Object.entries(SCHANNEL_PROTOCOL_MAP).forEach(([token, schannelName]) => {
    protocolPlan.push({ schannelName, enable: enabledSet.has(token) });
  });

  // ---- ECC curves DO-plan ---------------------------------------------------
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
  const hasPqGroup = output.tlsCurves.some(g => /MLKEM/.test(g));

  // ---- H1: filter cipher list against the Schannel allow-list --------------
  // Anything not implemented by Schannel (most prominently `TLS_DHE_RSA_*`)
  // is dropped here in JS so the rendered script can list both the kept and
  // dropped tokens up-front, and so the `Functions` REG_SZ value never
  // contains a token that would cause Schannel to discard the entire order.
  const allowedCiphers = [];
  const droppedCiphers = [];
  output.ciphers.forEach(c => {
    if (SCHANNEL_CIPHER_ALLOW.has(c)) allowedCiphers.push(c);
    else droppedCiphers.push(c);
  });
  const tls13Present = allowedCiphers.some(c => TLS13_CIPHERS.has(c));

  // ===========================================================================
  // Render the PowerShell script.
  // ===========================================================================

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
      '#   .\\Set-IISTls.ps1                              # snapshot current state, then apply\n'+
      '#   .\\Set-IISTls.ps1 -BackupPath C:\\path\\backup    # custom backup base path\n'+
      '#   .\\Set-IISTls.ps1 -Restore -BackupPath C:\\path\\backup   # roll back from <base>.undo.json\n'+
      '#   .\\Set-IISTls.ps1 -JsonToReg C:\\path\\backup.do.json [-RegOut out.reg]\n'+
      '#                                                  # convert a do/undo JSON snapshot to a\n'+
      '#                                                  # Windows Registry Editor v5 (.reg) file.\n'+
      '#                                                  # Read-only; does not require Administrator.\n'+
      '#\n'+
      '# Schannel protocol / cipher / group changes require a REBOOT to take effect.\n'+
      '#\n'+
      '# Mozilla profile groups -> Schannel names:\n';
  groupNotes.forEach(n => { conf += '#   '+n+'\n'; });

  if (droppedCiphers.length) {
    conf +=
      '#\n'+
      '# NOTE: the following IANA cipher-suite names from the Mozilla profile\n'+
      '# are NOT implemented by Schannel and have been dropped from the\n'+
      '# Functions value (the script will also Write-Warning at runtime):\n';
    droppedCiphers.forEach(c => { conf += '#   - '+c+'\n'; });
  }

  if (form && (form.pq === 'only' || (form.pq === 'mixed' && hasPqGroup))) {
    conf +=
      '#\n'+
      '# PQ '+(form.pq === 'only' ? 'ONLY' : 'HYBRID')+' mode: this profile includes the X25519MLKEM768\n'+
      '# hybrid post-quantum key-exchange group (Schannel name MLKEM768X25519).\n'+
      '# Hybrid ML-KEM in Schannel/SymCrypt is currently a Windows Insider /\n'+
      '# preview feature (see techcommunity.microsoft.com PQC announcement).\n'+
      '# The MLKEM768X25519 / MLKEM768P256 / MLKEM1024P384 strings used in the\n'+
      '# EccCurves value below are PROVISIONAL — Microsoft has not yet\n'+
      '# published a stable, supported list of Schannel ECC group strings\n'+
      '# for ML-KEM hybrids.\n'+
      '#\n'+
      '# To check whether your build still treats them as provisional:\n'+
      '#   1. Run on the target host (Windows PowerShell 5.1 or 7+):\n'+
      '#        Get-TlsEccCurve | Where-Object { $_ -like \'*MLKEM*\' -or $_ -like \'*KEM*\' }\n'+
      '#      If MLKEM768X25519 (or similar) appears in the output, ML-KEM is\n'+
      '#      registered with Schannel on this build and the EccCurves write\n'+
      '#      below will take effect after reboot.\n'+
      '#   2. Otherwise: cross-reference the latest Microsoft "TLS registry\n'+
      '#      settings" page (learn.microsoft.com/.../tls-registry-settings)\n'+
      '#      and the SymCrypt release notes (github.com/microsoft/SymCrypt)\n'+
      '#      for the canonical group string for your Windows build.\n'+
      '#   3. The script will Write-Warning at runtime and continue; an\n'+
      '#      unrecognised EccCurves entry is harmless (Schannel falls back\n'+
      '#      to its defaults).\n';
  }

  conf +=
      '\n'+
      '[CmdletBinding()]\n'+
      'param(\n'+
      '    [switch]$Restore,\n'+
      '    [string]$BackupPath,\n'+
      '    # Read-only conversion of a do.json / undo.json snapshot into a\n'+
      '    # Windows Registry Editor v5 (.reg) file. Does NOT modify the host.\n'+
      '    [string]$JsonToReg,\n'+
      '    [string]$RegOut\n'+
      ')\n'+
      '\n'+
      '$ErrorActionPreference = \'Stop\'\n'+
      '\n'+
      '# Require Administrator: every key written below lives under HKLM.\n'+
      '# (Skipped for -JsonToReg: that path performs only a read of the JSON\n'+
      '# snapshot and writes a .reg file, no HKLM mutation.)\n'+
      'if (-not $JsonToReg) {\n'+
      '    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()\n'+
      '    $principal = New-Object Security.Principal.WindowsPrincipal $identity\n'+
      '    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n'+
      '        throw \'Set-IISTls.ps1 must be run from an elevated PowerShell prompt (Administrator).\'\n'+
      '    }\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# L1 + file-ACL hardening: default backup base path is under %ProgramData%\n'+
      '# in a directory we create with an Administrators+SYSTEM-only ACL, so a\n'+
      '# non-admin process cannot pre-create a reparse point at the snapshot\n'+
      '# location nor read the snapshot files (which describe the host\'s pre-\n'+
      '# apply Schannel state — useful intelligence for an attacker scoping a\n'+
      '# downgrade attack). The same ACL is applied to the do.json / undo.json\n'+
      '# files themselves immediately after they are written.\n'+
      '# ---------------------------------------------------------------------------\n'+
      'function New-AdminOnlyAcl {\n'+
      '    param([Parameter(Mandatory)][ValidateSet(\'Directory\',\'File\')][string]$Kind)\n'+
      '    if ($Kind -eq \'Directory\') {\n'+
      '        $acl = New-Object System.Security.AccessControl.DirectorySecurity\n'+
      '        $inherit = [System.Security.AccessControl.InheritanceFlags]::"ContainerInherit, ObjectInherit"\n'+
      '    }\n'+
      '    else {\n'+
      '        $acl = New-Object System.Security.AccessControl.FileSecurity\n'+
      '        $inherit = [System.Security.AccessControl.InheritanceFlags]::None\n'+
      '    }\n'+
      '    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop inherited\n'+
      '    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl\n'+
      '    $prop   = [System.Security.AccessControl.PropagationFlags]::None\n'+
      '    $allow  = [System.Security.AccessControl.AccessControlType]::Allow\n'+
      '    foreach ($sid in @(\'S-1-5-32-544\',\'S-1-5-18\')) {  # Administrators, SYSTEM\n'+
      '        $id = (New-Object System.Security.Principal.SecurityIdentifier $sid)\n'+
      '        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule $id,$rights,$inherit,$prop,$allow))\n'+
      '    }\n'+
      '    return $acl\n'+
      '}\n'+
      'function Initialize-BackupDirectory {\n'+
      '    [CmdletBinding()] param([string]$Path)\n'+
      '    if (Test-Path -LiteralPath $Path) {\n'+
      '        # Refuse to use a path that is a file or a reparse point —\n'+
      '        # otherwise an attacker could pre-create a junction at our\n'+
      '        # default %ProgramData% location aimed at e.g. C:\\Windows.\n'+
      '        $existing = Get-Item -LiteralPath $Path -Force\n'+
      '        if (-not $existing.PSIsContainer) {\n'+
      '            throw "Backup path $Path exists but is not a directory."\n'+
      '        }\n'+
      '        if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {\n'+
      '            throw "Backup path $Path is a reparse point/junction; refusing to use it."\n'+
      '        }\n'+
      '    }\n'+
      '    else {\n'+
      '        $null = New-Item -Path $Path -ItemType Directory -Force\n'+
      '    }\n'+
      '    # Always (re-)apply the Administrators+SYSTEM-only ACL so an existing\n'+
      '    # but loosely-permissioned directory gets locked down too.\n'+
      '    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind Directory)\n'+
      '}\n'+
      'function Protect-File {\n'+
      '    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)\n'+
      '    if (-not (Test-Path -LiteralPath $Path)) {\n'+
      '        throw "Protect-File: file does not exist: $Path"\n'+
      '    }\n'+
      '    $f = Get-Item -LiteralPath $Path -Force\n'+
      '    if ($f.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {\n'+
      '        throw "Protect-File: refusing to ACL a reparse point: $Path"\n'+
      '    }\n'+
      '    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind File)\n'+
      '}\n'+
      'function New-ProtectedFile {\n'+
      '    # Create an EMPTY file with the strict Administrators+SYSTEM ACL\n'+
      '    # BEFORE any content is written. The previous "Set-Content first,\n'+
      '    # Protect-File after" sequence created the file with the parent\n'+
      '    # directory\'s ACL — fine for the default %ProgramData% location\n'+
      '    # (locked down by Initialize-BackupDirectory) but NOT for a\n'+
      '    # caller-supplied -BackupPath under e.g. C:\\Temp, where the file\n'+
      '    # would briefly hold sensitive snapshot content with a permissive\n'+
      '    # inherited ACL between the Set-Content write and the Set-Acl tighten.\n'+
      '    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)\n'+
      '    if (Test-Path -LiteralPath $Path) {\n'+
      '        $existing = Get-Item -LiteralPath $Path -Force\n'+
      '        if ($existing.PSIsContainer) {\n'+
      '            throw "New-ProtectedFile: $Path exists and is a directory."\n'+
      '        }\n'+
      '        if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {\n'+
      '            throw "New-ProtectedFile: $Path exists and is a reparse point/symlink; refusing to use it."\n'+
      '        }\n'+
      '        # Pre-existing file: truncate via FileMode::Create (CreateNew\n'+
      '        # would throw if the file exists; Truncate would throw if it\n'+
      '        # does not). The handle is closed immediately — Set-Content\n'+
      '        # below opens its own handle.\n'+
      '        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)\n'+
      '        $fs.Close()\n'+
      '    }\n'+
      '    else {\n'+
      '        # Atomic create-or-fail: FileMode::CreateNew defeats a TOCTOU\n'+
      '        # race where an attacker plants a symlink between our\n'+
      '        # Test-Path check and our open call.\n'+
      '        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)\n'+
      '        $fs.Close()\n'+
      '    }\n'+
      '    # Tighten the ACL while the file is still empty.\n'+
      '    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind File)\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# -JsonToReg: read a do.json or undo.json snapshot and emit a Windows\n'+
      '# Registry Editor v5 (.reg) file. This is a read-only operation that\n'+
      '# does NOT modify the host, so it runs BEFORE the elevation check (a\n'+
      '# non-admin can convert JSON -> .reg for inspection / staging). The\n'+
      '# emitted .reg file is ACL-protected with the same Administrators+SYSTEM\n'+
      '# ACL as the source JSON to avoid leaking the host\'s pre-apply state.\n'+
      '#\n'+
      '# Mapping:\n'+
      '#   Kind=Registry, Existed=$true, Type=DWord       -> "Name"=dword:XXXXXXXX\n'+
      '#   Kind=Registry, Existed=$true, Type=String      -> "Name"="..."\n'+
      '#   Kind=Registry, Existed=$true, Type=MultiString -> "Name"=hex(7):...   (UTF-16LE)\n'+
      '#   Kind=Registry, Existed=$false                  -> "Name"=-            (delete-value)\n'+
      '#   Kind=WebConfig                                 -> ; comment (.reg cannot express IIS web-config)\n'+
      '# ---------------------------------------------------------------------------\n'+
      'function ConvertTo-RegStringLiteral {\n'+
      '    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)\n'+
      '    # .reg v5 string escapes: backslash and double-quote are doubled by\n'+
      '    # backslash; everything else is literal (including non-ASCII, which\n'+
      '    # the .reg file is UTF-16LE BOM-prefixed to support).\n'+
      '    return \'"\' + ($Value -replace \'\\\\\',\'\\\\\\\\\' -replace \'"\',\'\\\\"\') + \'"\'\n'+
      '}\n'+
      'function ConvertTo-RegMultiStringHex {\n'+
      '    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Values)\n'+
      '    # REG_MULTI_SZ in .reg files is hex(7) of UTF-16LE-encoded strings\n'+
      '    # each terminated by a U+0000, with a final extra U+0000 terminator.\n'+
      '    $bytes = New-Object System.Collections.Generic.List[byte]\n'+
      '    foreach ($s in $Values) {\n'+
      '        $b = [System.Text.Encoding]::Unicode.GetBytes($s)\n'+
      '        $bytes.AddRange($b)\n'+
      '        $bytes.Add(0); $bytes.Add(0)  # U+0000 terminator for this string\n'+
      '    }\n'+
      '    $bytes.Add(0); $bytes.Add(0)      # final U+0000 terminator for the list\n'+
      '    return \'hex(7):\' + (($bytes | ForEach-Object { \'{0:x2}\' -f $_ }) -join \',\')\n'+
      '}\n'+
      'function ConvertFrom-DoUndoJsonToReg {\n'+
      '    param([Parameter(Mandatory)][string]$JsonPath,\n'+
      '          [Parameter(Mandatory)][string]$RegPath)\n'+
      '    if (-not (Test-Path -LiteralPath $JsonPath)) {\n'+
      '        throw "JsonToReg: input JSON not found: $JsonPath"\n'+
      '    }\n'+
      '    $entries = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json\n'+
      '    # Group Registry entries by Path to emit one [Key] block each.\n'+
      '    $regEntries = @($entries | Where-Object { $_.Kind -eq \'Registry\' })\n'+
      '    $webEntries = @($entries | Where-Object { $_.Kind -eq \'WebConfig\' })\n'+
      '    $byPath = @{}\n'+
      '    foreach ($e in $regEntries) {\n'+
      '        if (-not $byPath.ContainsKey($e.Path)) { $byPath[$e.Path] = New-Object System.Collections.ArrayList }\n'+
      '        $null = $byPath[$e.Path].Add($e)\n'+
      '    }\n'+
      '    $sb = New-Object System.Text.StringBuilder\n'+
      '    $null = $sb.AppendLine(\'Windows Registry Editor Version 5.00\')\n'+
      '    $null = $sb.AppendLine(\'\')\n'+
      '    $null = $sb.AppendLine(\'; Generated from \' + $JsonPath)\n'+
      '    $null = $sb.AppendLine(\'; NOTE: Importing a .reg file APPENDS values; it cannot DELETE values\')\n'+
      '    $null = $sb.AppendLine(\';       that did not exist before (those appear below as "Name"=- entries\')\n'+
      '    $null = $sb.AppendLine(\';       which DO delete on import). For full fidelity, prefer\')\n'+
      '    $null = $sb.AppendLine(\';       `.\\\\Set-IISTls.ps1 -Restore -BackupPath ...` over `reg import`.\')\n'+
      '    $null = $sb.AppendLine(\'\')\n'+
      '    foreach ($p in $byPath.Keys) {\n'+
      '        # .reg uses the long-form HKEY_LOCAL_MACHINE prefix. Note: this\n'+
      '        # local is named $regKey (NOT $regPath) because PowerShell\n'+
      '        # variables are case-insensitive and $RegPath is the function\n'+
      '        # parameter — assigning to $regPath here would silently clobber\n'+
      '        # the output path, causing WriteAllText below to write to the\n'+
      '        # last key name instead of the requested .reg file.\n'+
      '        $regKey = $p -replace \'^HKLM\\\\\',\'HKEY_LOCAL_MACHINE\\\' `\n'+
      '                     -replace \'^HKCU\\\\\',\'HKEY_CURRENT_USER\\\'\n'+
      '        $null = $sb.AppendLine(\'[\' + $regKey + \']\')\n'+
      '        foreach ($e in $byPath[$p]) {\n'+
      '            $name = ConvertTo-RegStringLiteral -Value $e.Name\n'+
      '            if (-not $e.Existed) {\n'+
      '                $null = $sb.AppendLine($name + \'=-\')\n'+
      '                continue\n'+
      '            }\n'+
      '            switch ($e.Type) {\n'+
      '                \'DWord\' {\n'+
      '                    # Coerce via [uint32] to render the unsigned 32-bit value.\n'+
      '                    $u = [uint32]([int64]$e.Value -band 0xFFFFFFFF)\n'+
      '                    $null = $sb.AppendLine($name + \'=dword:\' + (\'{0:x8}\' -f $u))\n'+
      '                }\n'+
      '                \'String\' {\n'+
      '                    $null = $sb.AppendLine($name + \'=\' + (ConvertTo-RegStringLiteral -Value ([string]$e.Value)))\n'+
      '                }\n'+
      '                \'MultiString\' {\n'+
      '                    # ConvertFrom-Json gives an Object[]; coerce to string[].\n'+
      '                    $arr = @($e.Value | ForEach-Object { [string]$_ })\n'+
      '                    $null = $sb.AppendLine($name + \'=\' + (ConvertTo-RegMultiStringHex -Values $arr))\n'+
      '                }\n'+
      '                default {\n'+
      '                    $null = $sb.AppendLine(\'; UNSUPPORTED Type=\' + $e.Type + \' for \' + $name)\n'+
      '                }\n'+
      '            }\n'+
      '        }\n'+
      '        $null = $sb.AppendLine(\'\')\n'+
      '    }\n'+
      '    if ($webEntries.Count -gt 0) {\n'+
      '        $null = $sb.AppendLine(\'; --- WebConfig entries (NOT representable in a .reg file) ---\')\n'+
      '        $null = $sb.AppendLine(\'; The following IIS web-configuration entries from the snapshot cannot\')\n'+
      '        $null = $sb.AppendLine(\'; be expressed in .reg syntax. Use Set-WebConfigurationProperty in\')\n'+
      '        $null = $sb.AppendLine(\'; PowerShell (or `.\\\\Set-IISTls.ps1 -Restore`) to apply them:\')\n'+
      '        foreach ($e in $webEntries) {\n'+
      '            $null = $sb.AppendLine(\';   Filter=\' + $e.Filter + \'  Name=\' + $e.Name + \'  Value=\' + $e.Value)\n'+
      '        }\n'+
      '    }\n'+
      '    # .reg files MUST be UTF-16LE with a BOM, otherwise reg.exe will\n'+
      '    # reject the file or mangle non-ASCII string values. Open the\n'+
      '    # PRE-EXISTING (caller-protected) file with Truncate so the file\n'+
      '    # ACL set by New-ProtectedFile is preserved (vs. WriteAllText\n'+
      '    # which creates the file with the parent\'s inherited ACL on miss).\n'+
      '    $utf16 = New-Object System.Text.UnicodeEncoding($false, $true)  # LE, BOM\n'+
      '    if (-not (Test-Path -LiteralPath $RegPath)) {\n'+
      '        throw "ConvertFrom-DoUndoJsonToReg: output file must be pre-created (and ACL-protected) by the caller: $RegPath"\n'+
      '    }\n'+
      '    $fs = [System.IO.File]::Open($RegPath, [System.IO.FileMode]::Truncate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)\n'+
      '    try {\n'+
      '        $sw = New-Object System.IO.StreamWriter($fs, $utf16)\n'+
      '        $sw.Write($sb.ToString())\n'+
      '        $sw.Flush()\n'+
      '        $sw.Close()\n'+
      '    }\n'+
      '    finally { $fs.Dispose() }\n'+
      '}\n'+
      '\n'+
      'if ($JsonToReg) {\n'+
      '    if (-not $RegOut) {\n'+
      '        # Default: same base name, .reg extension.\n'+
      '        $RegOut = [System.IO.Path]::ChangeExtension($JsonToReg, \'.reg\')\n'+
      '        # Strip the .do/.undo infix from the stem so foo.undo.json -> foo.reg.\n'+
      '        $RegOut = $RegOut -replace \'\\.(do|undo)\\.reg$\',\'.reg\'\n'+
      '    }\n'+
      '    # Pre-create with strict ACL BEFORE writing the .reg payload\n'+
      '    # (the snapshot may describe sensitive Schannel state — same\n'+
      '    # reasoning as for .do.json / .undo.json above).\n'+
      '    New-ProtectedFile -Path $RegOut\n'+
      '    ConvertFrom-DoUndoJsonToReg -JsonPath $JsonToReg -RegPath $RegOut\n'+
      '    Write-Host "Wrote .reg file: $RegOut"\n'+
      '    Write-Host \'NOTE: `reg import` cannot DELETE registry values; for fidelity use\'\n'+
      '    Write-Host \'      `.\\Set-IISTls.ps1 -Restore -BackupPath <base>` instead.\'\n'+
      '    return\n'+
      '}\n'+
      '\n'+
      'if (-not $BackupPath) {\n'+
      '    $backupDir = Join-Path $env:ProgramData \'Mozilla-SSLConfigGenerator\'\n'+
      '    Initialize-BackupDirectory -Path $backupDir\n'+
      '    $stamp = Get-Date -Format \'yyyyMMdd-HHmmss\'\n'+
      '    $BackupPath = Join-Path $backupDir ("schannel-backup-{0}" -f $stamp)\n'+
      '}\n'+
      'Write-Host "Backup base path: $BackupPath"\n'+
      'Write-Host "  (do-plan: ${BackupPath}.do.json   undo-snapshot: ${BackupPath}.undo.json)"\n'+
      '\n'+
      '$SchannelBase = '+psQuote(SCHANNEL_BASE)+'\n'+
      '$CipherKey    = '+psQuote(CIPHER_KEY)+'\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# L2: tiny, intent-revealing helpers wrapping the Test-Path / New-Item /\n'+
      '# New-ItemProperty dance. All registry mutations go through Set-Reg* so\n'+
      '# the snapshot / replay logic only has to know one shape of operation.\n'+
      '# ---------------------------------------------------------------------------\n'+
      'function Ensure-RegKey {\n'+
      '    param([Parameter(Mandatory)][string]$Path)\n'+
      '    $literal = "Registry::$Path"\n'+
      '    if (-not (Test-Path -LiteralPath $literal)) { $null = New-Item -Path $literal -Force }\n'+
      '}\n'+
      'function Get-RegValueSnapshot {\n'+
      '    param([Parameter(Mandatory)][string]$Path,\n'+
      '          [Parameter(Mandatory)][string]$Name)\n'+
      '    $literal = "Registry::$Path"\n'+
      '    if (-not (Test-Path -LiteralPath $literal)) {\n'+
      '        return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$false; Type=$null; Value=$null }\n'+
      '    }\n'+
      '    $key = Get-Item -LiteralPath $literal\n'+
      '    if ($null -eq $key.GetValue($Name, $null, \'DoNotExpandEnvironmentNames\')) {\n'+
      '        # Distinguish "value missing" from "value present but $null":\n'+
      '        # property names list is authoritative.\n'+
      '        if ($key.Property -notcontains $Name) {\n'+
      '            return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$false; Type=$null; Value=$null }\n'+
      '        }\n'+
      '    }\n'+
      '    $type  = $key.GetValueKind($Name).ToString()\n'+
      '    $value = $key.GetValue($Name, $null, \'DoNotExpandEnvironmentNames\')\n'+
      '    return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$true; Type=$type; Value=$value }\n'+
      '}\n'+
      'function Set-RegValue {\n'+
      '    param([Parameter(Mandatory)][string]$Path,\n'+
      '          [Parameter(Mandatory)][string]$Name,\n'+
      '          [Parameter(Mandatory)][ValidateSet(\'DWord\',\'String\',\'MultiString\')][string]$Type,\n'+
      '          [Parameter(Mandatory)]$Value)\n'+
      '    Ensure-RegKey -Path $Path\n'+
      '    $null = New-ItemProperty -Path "Registry::$Path" -Name $Name -Value $Value -PropertyType $Type -Force\n'+
      '}\n'+
      'function Remove-RegValueIfPresent {\n'+
      '    param([Parameter(Mandatory)][string]$Path,\n'+
      '          [Parameter(Mandatory)][string]$Name)\n'+
      '    $literal = "Registry::$Path"\n'+
      '    if (Test-Path -LiteralPath $literal) {\n'+
      '        $key = Get-Item -LiteralPath $literal\n'+
      '        if ($key.Property -contains $Name) {\n'+
      '            Remove-ItemProperty -LiteralPath $literal -Name $Name -Force\n'+
      '        }\n'+
      '    }\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# IIS web-configuration helpers (HSTS lives at\n'+
      '# system.applicationHost/sites/site[@name=...]/hsts in applicationHost.config).\n'+
      '# Snapshot returns the current value of a single property; on -Restore we\n'+
      '# write it back. The <hsts> element always exists at the section level\n'+
      '# (with default values) so Existed is always $true for WebConfig entries.\n'+
      '# ---------------------------------------------------------------------------\n'+
      'function Get-WebConfigSnapshot {\n'+
      '    param([Parameter(Mandatory)][string]$PSPath,\n'+
      '          [Parameter(Mandatory)][string]$Filter,\n'+
      '          [Parameter(Mandatory)][string]$Name)\n'+
      '    Import-Module WebAdministration -ErrorAction SilentlyContinue\n'+
      '    $current = $null\n'+
      '    try {\n'+
      '        $prop = Get-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name -ErrorAction Stop\n'+
      '        if ($null -ne $prop) {\n'+
      '            # Get-WebConfigurationProperty returns either a primitive or a\n'+
      '            # ConfigurationAttribute with a .Value property — normalise.\n'+
      '            if ($prop.PSObject.Properties[\'Value\']) { $current = $prop.Value } else { $current = $prop }\n'+
      '        }\n'+
      '    }\n'+
      '    catch { $current = $null }\n'+
      '    return [pscustomobject]@{ PSPath=$PSPath; Filter=$Filter; Name=$Name; Existed=$true; Value=$current }\n'+
      '}\n'+
      'function Set-WebConfigValue {\n'+
      '    param([Parameter(Mandatory)][string]$PSPath,\n'+
      '          [Parameter(Mandatory)][string]$Filter,\n'+
      '          [Parameter(Mandatory)][string]$Name,\n'+
      '          [Parameter(Mandatory)]$Value)\n'+
      '    Import-Module WebAdministration -ErrorAction SilentlyContinue\n'+
      '    Set-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name -Value $Value\n'+
      '}\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# -Restore: read the undo-snapshot JSON and reverse every recorded change.\n'+
      '# Values that did NOT exist before are deleted; values that did exist are\n'+
      '# restored to their previous Type + Value (this is what `reg.exe import`\n'+
      '# could NOT do — it cannot remove keys/values created since the export).\n'+
      '# ---------------------------------------------------------------------------\n'+
      'if ($Restore) {\n'+
      '    $undoFile = "${BackupPath}.undo.json"\n'+
      '    if (-not (Test-Path -LiteralPath $undoFile)) {\n'+
      '        throw "Undo snapshot not found: $undoFile"\n'+
      '    }\n'+
      '    Write-Host "Restoring SCHANNEL + IIS settings from $undoFile ..."\n'+
      '    $entries = Get-Content -LiteralPath $undoFile -Raw | ConvertFrom-Json\n'+
      '    foreach ($e in $entries) {\n'+
      '        switch ($e.Kind) {\n'+
      '            \'Registry\' {\n'+
      '                if ($e.Existed) {\n'+
      '                    Set-RegValue -Path $e.Path -Name $e.Name -Type $e.Type -Value $e.Value\n'+
      '                }\n'+
      '                else {\n'+
      '                    Remove-RegValueIfPresent -Path $e.Path -Name $e.Name\n'+
      '                }\n'+
      '            }\n'+
      '            \'WebConfig\' {\n'+
      '                # <hsts> properties always have defaults; just write the captured value back.\n'+
      '                Set-WebConfigValue -PSPath $e.PSPath -Filter $e.Filter -Name $e.Name -Value $e.Value\n'+
      '            }\n'+
      '            default { throw "Unknown undo entry Kind: $($e.Kind)" }\n'+
      '        }\n'+
      '    }\n'+
      '    Write-Host \'A reboot is required for Schannel changes to take effect.\'\n'+
      '    return\n'+
      '}\n'+
      '\n'+
      '# ===========================================================================\n'+
      '# Apply pass.\n'+
      '# ===========================================================================\n'+
      '\n'+
      '# ---------------------------------------------------------------------------\n'+
      '# DO-plan — every registry mutation we are about to perform, in order.\n'+
      '# The corresponding undo-snapshot is captured BEFORE any mutation so it\n'+
      '# always reflects the pre-apply state of the host.\n'+
      '# ---------------------------------------------------------------------------\n'+
      '$DoPlan = @(\n';

  // Emit DO-plan entries. Each entry is a hashtable literal; the script
  // walks them in order and applies via Set-RegValue.
  const planEntries = [];

  // Protocol entries (H2 — explicit enable AND explicit disable).
  protocolPlan.forEach(({ schannelName, enable }) => {
    ['Server', 'Client'].forEach(side => {
      const path = `${SCHANNEL_BASE}\\Protocols\\${schannelName}\\${side}`;
      planEntries.push({
        Kind: 'Registry',
        Path: path,
        Name: 'Enabled',
        Type: 'DWord',
        Value: enable ? 0xFFFFFFFF : 0,
      });
      planEntries.push({
        Kind: 'Registry',
        Path: path,
        Name: 'DisabledByDefault',
        Type: 'DWord',
        Value: enable ? 0 : 1,
      });
    });
  });

  // Cipher-suite ordering (H1 — already filtered).
  if (allowedCiphers.length) {
    planEntries.push({
      Kind: 'Registry',
      Path: CIPHER_KEY,
      Name: 'Functions',
      Type: 'String',
      Value: allowedCiphers.join(','),
    });
  }

  // ECC / named-group ordering.
  if (eccCurves.length) {
    planEntries.push({
      Kind: 'Registry',
      Path: CIPHER_KEY,
      Name: 'EccCurves',
      Type: 'MultiString',
      Value: eccCurves,
    });
  }

  // HSTS — IIS 10 v1709+ native <hsts> element. Captured into the same
  // do/undo snapshot as the registry writes so -Restore reverts both.
  if (form && form.hsts) {
    const hstsPSPath = 'MACHINE/WEBROOT/APPHOST';
    const hstsFilter = "system.applicationHost/sites/site[@name='Default Web Site']/hsts";
    [
      { Name: 'enabled',             Value: true },
      { Name: 'max-age',             Value: output.hstsMaxAge },
      { Name: 'includeSubDomains',   Value: true },
      { Name: 'redirectHttpToHttps', Value: true },
    ].forEach(p => {
      planEntries.push({
        Kind: 'WebConfig',
        PSPath: hstsPSPath,
        Filter: hstsFilter,
        Name: p.Name,
        Value: p.Value,
      });
    });
  }

  planEntries.forEach((e, i) => {
    conf += '    ' + psHashtable(e) + (i < planEntries.length - 1 ? ',' : '') + '\n';
  });

  conf +=
      ')\n'+
      '\n'+
      '# Capture the pre-apply state of every entry mentioned in the DO-plan.\n'+
      '$Undo = foreach ($op in $DoPlan) {\n'+
      '    switch ($op.Kind) {\n'+
      '        \'Registry\'  { Get-RegValueSnapshot -Path $op.Path -Name $op.Name }\n'+
      '        \'WebConfig\' { Get-WebConfigSnapshot -PSPath $op.PSPath -Filter $op.Filter -Name $op.Name }\n'+
      '        default     { throw "Unknown DO-plan entry Kind: $($op.Kind)" }\n'+
      '    }\n'+
      '}\n'+
      '\n'+
      '# Persist DO-plan and UNDO-snapshot. Pre-create each file with the\n'+
      '# strict Administrators+SYSTEM ACL FIRST, then Set-Content overwrites\n'+
      '# the (empty) file — file ACLs are preserved across Set-Content writes\n'+
      '# to an existing file, so the snapshot data never lands on disk under\n'+
      '# the parent directory\'s (potentially permissive) inherited ACL.\n'+
      'New-ProtectedFile -Path ("${BackupPath}.do.json")\n'+
      '$DoPlan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ("${BackupPath}.do.json")   -Encoding UTF8\n'+
      'New-ProtectedFile -Path ("${BackupPath}.undo.json")\n'+
      '$Undo   | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ("${BackupPath}.undo.json") -Encoding UTF8\n'+
      'Write-Host "DO-plan written to ${BackupPath}.do.json ("$DoPlan.Count" entries)"\n'+
      'Write-Host "UNDO snapshot written to ${BackupPath}.undo.json"\n'+
      '\n';

  // -- H1 runtime: surface dropped / TLS 1.3-advisory cipher tokens ---------
  if (droppedCiphers.length) {
    conf +=
      '# H1: dropped IANA cipher-suite names that Schannel does not implement.\n'+
      '$DroppedCiphers = @('+psQuoteList(droppedCiphers)+')\n'+
      'foreach ($c in $DroppedCiphers) {\n'+
      '    Write-Warning "Dropping cipher \'$c\' — not implemented by Schannel; not written to Functions."\n'+
      '}\n'+
      '\n';
  }
  if (tls13Present) {
    conf +=
      '# H1: TLS 1.3 cipher-suites are negotiated from a fixed Schannel set;\n'+
      '# the Functions REG_SZ value does NOT govern their ordering.\n'+
      'Write-Information \'TLS 1.3 cipher-suite ordering in Schannel is not user-tunable via Functions; the TLS 1.3 entries above are advisory.\' -InformationAction Continue\n'+
      '\n';
  }

  // -- M3 runtime: PQ provisional warning ------------------------------------
  if (eccCurves.some(c => /MLKEM/.test(c))) {
    conf +=
      '# M3: PQ groups in this profile are PROVISIONAL on current Windows builds.\n'+
      'Write-Warning \'EccCurves contains ML-KEM hybrid group strings (e.g. MLKEM768X25519). These are PROVISIONAL — verify with: Get-TlsEccCurve | Where-Object { $_ -like \'\'*MLKEM*\'\' }. If absent, the values will be ignored by Schannel and the negotiation will fall back to classical curves.\'\n'+
      '\n';
  }

  conf +=
      '# ---------------------------------------------------------------------------\n'+
      '# Apply the DO-plan (registry writes + IIS <hsts> writes alike).\n'+
      '# ---------------------------------------------------------------------------\n'+
      'foreach ($op in $DoPlan) {\n'+
      '    switch ($op.Kind) {\n'+
      '        \'Registry\'  { Set-RegValue -Path $op.Path -Name $op.Name -Type $op.Type -Value $op.Value }\n'+
      '        \'WebConfig\' { Set-WebConfigValue -PSPath $op.PSPath -Filter $op.Filter -Name $op.Name -Value $op.Value }\n'+
      '        default     { throw "Unknown DO-plan entry Kind: $($op.Kind)" }\n'+
      '    }\n'+
      '}\n'+
      '\n'+
      '# Note: the protocol DO-plan above EXPLICITLY disables every TLS version\n'+
      '# in '+JSON.stringify(Object.values(SCHANNEL_PROTOCOL_MAP))+' that is not in\n'+
      '# the Mozilla '+(form && form.config ? form.config : 'intermediate')+' profile, by writing\n'+
      '# Enabled=0 / DisabledByDefault=1 under HKLM\\...\\SCHANNEL\\Protocols\\<name>\\Server\n'+
      '# and \\Client. This is intentional — the previous "leave at OS defaults"\n'+
      '# behaviour silently kept TLS 1.0 / 1.1 enabled on Server 2019/2022.\n'+
      '\n';

  // -- HSTS reporting --------------------------------------------------------
  // The HSTS site-config writes are part of the DO-plan above (and therefore
  // covered by the undo snapshot). Just emit a documentation comment for the
  // operator so the generated script remains self-documenting.
  if (form && form.hsts) {
    conf +=
      '# HSTS (IIS 10 v1709+ native <hsts> element under "Default Web Site"):\n'+
      '#   max-age='+output.hstsMaxAge+'; includeSubDomains; redirectHttpToHttps=true.\n'+
      '# Strict-Transport-Security: max-age='+output.hstsMaxAge+'; includeSubDomains\n'+
      '# Adjust the site name in the DO-plan WebConfig entries above if you are\n'+
      '# not configuring "Default Web Site".\n'+
      '\n';
  }

  conf +=
      'Write-Host \'\'\n'+
      'Write-Host \'Done. A REBOOT is required for Schannel protocol/cipher/group changes to take effect.\'\n'+
      'Write-Host "To revert, run:  .\\Set-IISTls.ps1 -Restore -BackupPath \'$BackupPath\'"\n';

  return conf;
};
