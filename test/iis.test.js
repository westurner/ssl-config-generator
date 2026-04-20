// IIS / Schannel PowerShell helper — generic-suite tests via the shared harness
// plus IIS-specific assertions for the do/undo snapshot mechanism, the Schannel
// cipher allow-list, the explicit-disable protocol policy, the PROVISIONAL PQ
// warning, and the ProgramData-rooted backup directory.
import assert from 'node:assert/strict';
import { runStandardHelperSuite } from './_helpers/harness.js';
import { makeForm, makeOutput, PQ_MODES } from './_helpers/fixtures.js';
import iis from '../src/js/helpers/iis.js';

runStandardHelperSuite({
  name: 'iis',
  helper: iis,
  serverVersion: '10.0.26100',
  cipherFormat: 'iana',
  supportsHsts: true,
  supportsPq: true,
  protocolDirective: {
    // The DO-plan now also explicitly disables every other version, so a
    // simple "TLS 1.3 appears" check would also match disabled-version
    // entries (Value=0). Anchor on the Server-side Enabled=0xFFFFFFFF
    // (rendered as 4294967295 by psLiteral) DWord to assert the version is
    // really enabled.
    modern:       /Protocols\\TLS 1\.3\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
    intermediate: /Protocols\\TLS 1\.2\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
    old:          /Protocols\\TLS 1\.0\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
  },
  versionTokens: {
    // Match each version's ENABLED Server entry (Value=4294967295). For
    // versions NOT in output.protocols, the DO-plan still mentions
    // 'TLS 1.x' tokens (with Enabled=0), so anchoring on Enabled=4294967295
    // is what makes the harness's positive/negative gating check correct
    // under the new explicit-disable behaviour.
    'TLSv1':   /Protocols\\TLS 1\.0\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
    'TLSv1.1': /Protocols\\TLS 1\.1\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
    'TLSv1.2': /Protocols\\TLS 1\.2\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
    'TLSv1.3': /Protocols\\TLS 1\.3\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/,
  },
  hstsHeader: /Strict-Transport-Security:\s*max-age=63072000;\s*includeSubDomains/,
  extraTests: (t) => {
    // ---- L3: structural ordering of the rendered script -------------------
    t('script blocks appear in the expected order: helpers -> Restore branch -> apply', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      const idxAdmin     = out.indexOf('Administrator');
      const idxBackupDir = out.indexOf('Initialize-BackupDirectory');
      const idxRegHelper = out.indexOf('function Set-RegValue');
      const idxRestore   = out.search(/if \(\$Restore\)/);
      const idxDoPlan    = out.indexOf('$DoPlan = @(');
      const idxSnapshot  = out.indexOf('$Undo = foreach');
      const idxApply     = out.search(/Apply the DO-plan/);
      assert.ok(idxAdmin     > 0,           'elevation check missing');
      assert.ok(idxBackupDir > idxAdmin,    'BackupDirectory helper before elevation check');
      assert.ok(idxRegHelper > idxBackupDir,'Set-RegValue helper before BackupDirectory init');
      assert.ok(idxRestore   > idxRegHelper,'-Restore branch before Set-RegValue helper');
      assert.ok(idxDoPlan    > idxRestore,  'DO-plan declared before -Restore branch (must be after)');
      assert.ok(idxSnapshot  > idxDoPlan,   'snapshot capture must come AFTER DO-plan declaration');
      assert.ok(idxApply     > idxSnapshot, 'apply must come AFTER snapshot persistence');
    });

    // ---- M2: do/undo JSON snapshot mechanism ------------------------------
    t('emits do.json + undo.json snapshot/replay (no .reg export); -Restore reads undo.json', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // Plan & snapshot files
      assert.match(out, /\$\{BackupPath\}\.do\.json/);
      assert.match(out, /\$\{BackupPath\}\.undo\.json/);
      assert.match(out, /ConvertTo-Json[^\n]+do\.json/);
      assert.match(out, /ConvertTo-Json[^\n]+undo\.json/);
      // Restore branch reads the undo file via ConvertFrom-Json
      assert.match(out, /\$undoFile\s*=\s*"\$\{BackupPath\}\.undo\.json"/);
      assert.match(out, /Get-Content -LiteralPath \$undoFile -Raw \| ConvertFrom-Json/);
      // Restore branch dispatches on Kind and calls Set-RegValue / Remove-RegValueIfPresent
      assert.match(out, /switch \(\$e\.Kind\)/);
      assert.match(out, /Set-RegValue\s+-Path\s+\$e\.Path/);
      assert.match(out, /Remove-RegValueIfPresent\s+-Path\s+\$e\.Path/);
      // The old reg.exe export/import calls are gone (only doc-comment
      // mentions of `reg.exe import` remain to explain WHY the JSON
      // snapshot exists — those are inside `#` comments).
      const noncomment = out.split('\n').filter(l => !/^\s*#/.test(l)).join('\n');
      assert.ok(!/reg\.exe/.test(noncomment),
        'reg.exe invocations should be gone from executable PowerShell (only doc-comments may mention it)');
    });

    // ---- File-ACL hardening (follow-up requirement) -----------------------
    t('do.json + undo.json files are pre-created with strict ACL BEFORE Set-Content writes any data', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // Helpers are defined.
      assert.match(out, /function Protect-File/);
      assert.match(out, /function New-ProtectedFile/);
      assert.match(out, /function New-AdminOnlyAcl/);
      // The order MUST be: New-ProtectedFile (creates empty + ACLs) BEFORE
      // Set-Content (writes the snapshot data into the already-protected
      // file). The previous order (Set-Content -> Protect-File) created
      // the file with the parent dir's inherited ACL — fine for the
      // %ProgramData% default, but a leak for caller-supplied -BackupPath
      // pointing into a permissive parent directory.
      assert.match(out,
        /New-ProtectedFile -Path \("\$\{BackupPath\}\.do\.json"\)[\s\S]*?Set-Content -LiteralPath \("\$\{BackupPath\}\.do\.json"\)/,
        'do.json must be New-ProtectedFile then Set-Content');
      assert.match(out,
        /New-ProtectedFile -Path \("\$\{BackupPath\}\.undo\.json"\)[\s\S]*?Set-Content -LiteralPath \("\$\{BackupPath\}\.undo\.json"\)/,
        'undo.json must be New-ProtectedFile then Set-Content');
      // New-ProtectedFile uses FileMode::CreateNew (atomic create-or-fail)
      // to defeat a TOCTOU race where an attacker plants a symlink.
      assert.match(out, /\[System\.IO\.FileMode\]::CreateNew/);
      // It also tightens the ACL while the file is still empty.
      assert.match(out, /Set-Acl -Path \$Path -AclObject \(New-AdminOnlyAcl -Kind File\)/);
      // Both helpers refuse reparse points (defence against attacker-planted symlinks).
      assert.match(out, /Protect-File: refusing to ACL a reparse point/);
      assert.match(out, /New-ProtectedFile: \$Path exists and is a reparse point\/symlink; refusing to use it/);
    });

    t('Initialize-BackupDirectory ALWAYS (re-)applies the ACL and refuses reparse points / non-directories', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // The fix: Set-Acl must run on the directory whether or not it pre-existed
      // (the previous version skipped Set-Acl on a pre-existing dir, leaving a
      // loosely-permissioned %ProgramData%\Mozilla-SSLConfigGenerator if one
      // existed).
      assert.match(out,
        /function Initialize-BackupDirectory[\s\S]*?Set-Acl -Path \$Path -AclObject \(New-AdminOnlyAcl -Kind Directory\)/);
      // Reject non-directories and reparse points at the chosen path.
      assert.match(out, /not a directory/);
      assert.match(out, /reparse point\/junction; refusing to use it/);
    });

    // ---- -JsonToReg (follow-up requirement) -------------------------------
    t('exposes a -JsonToReg parameter that converts a do/undo JSON snapshot into a .reg file', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // Param block declares both the input JSON path and the output .reg path.
      assert.match(out, /\[string\]\$JsonToReg/);
      assert.match(out, /\[string\]\$RegOut/);
      // The branch runs ahead of the elevation check (read-only path).
      const idxAdminGate = out.search(/if \(-not \$JsonToReg\) \{[^}]*IsInRole/);
      assert.ok(idxAdminGate >= 0,
        'Administrator gate must be wrapped in `if (-not $JsonToReg)` so non-admins can convert JSON->reg');
      // Branch dispatch + early return. Order MUST be: New-ProtectedFile
      // (creates empty + ACLs) BEFORE ConvertFrom-DoUndoJsonToReg (writes
      // the .reg payload via Truncate into the already-protected file).
      assert.match(out, /if \(\$JsonToReg\) \{[\s\S]*New-ProtectedFile -Path \$RegOut[\s\S]*ConvertFrom-DoUndoJsonToReg[\s\S]*return\s*\n\s*\}/);
      // Helper function declarations.
      assert.match(out, /function ConvertTo-RegStringLiteral/);
      assert.match(out, /function ConvertTo-RegMultiStringHex/);
      assert.match(out, /function ConvertFrom-DoUndoJsonToReg/);
      // .reg v5 header is emitted.
      assert.match(out, /Windows Registry Editor Version 5\.00/);
      // Default $RegOut strips .do/.undo infix from the source name.
      assert.match(out, /\$RegOut = \$RegOut -replace\s+'\\\.\(do\|undo\)\\\.reg\$',\s*'\.reg'/);
    });

    t('-JsonToReg renders Registry entries in the correct .reg syntax for each Type', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // DWord rendering: zero-padded 8-digit lowercase hex via the {0:x8}
      // format specifier, masked to 32-bit unsigned.
      assert.match(out, /'=dword:'\s*\+\s*\('\{0:x8\}'\s*-f\s*\$u\)/);
      assert.match(out, /\[uint32\]\(\[int64\]\$e\.Value\s+-band 0xFFFFFFFF\)/);
      // String rendering uses ConvertTo-RegStringLiteral (escapes \\ and ").
      assert.match(out, /'String'\s*\{[\s\S]*?ConvertTo-RegStringLiteral -Value \(\[string\]\$e\.Value\)/);
      // MultiString -> hex(7) UTF-16LE byte stream with NUL terminators.
      assert.match(out, /'MultiString'\s*\{[\s\S]*?ConvertTo-RegMultiStringHex -Values \$arr/);
      assert.match(out, /'hex\(7\):'/);
      assert.match(out, /\[System\.Text\.Encoding\]::Unicode\.GetBytes/);
      // Existed=$false (value did not exist before apply) -> "Name"=- (delete-value)
      assert.match(out, /if \(-not \$e\.Existed\) \{[\s\S]*?\$name \+ '=-'/);
      // HKLM\... is rewritten to the long-form HKEY_LOCAL_MACHINE\... that
      // .reg files require. Note: the local must NOT be named $regPath
      // (PowerShell is case-insensitive and would clobber the $RegPath
      // parameter) — assert it is named $regKey instead. Also assert the
      // pattern matches `HKLM\` (regex `^HKLM\\`) and the replacement is a
      // SINGLE backslash (`HKEY_LOCAL_MACHINE\`), not two.
      assert.match(out, /\$regKey = \$p -replace\s+'\^HKLM\\\\','HKEY_LOCAL_MACHINE\\'/);
      assert.ok(!/\$regPath\s*=\s*\$p\s*-replace/.test(out),
        'inner local must not shadow the $RegPath parameter (PowerShell is case-insensitive)');
      // WebConfig entries cannot be expressed in .reg — emit `;` comments.
      assert.match(out, /WebConfig entries \(NOT representable in a \.reg file\)/);
      // .reg files MUST be UTF-16LE with BOM, otherwise reg.exe rejects them.
      assert.match(out, /System\.Text\.UnicodeEncoding\(\$false,\s*\$true\)/);
    });

    // ---- L3 (revisited): ordering with the new -JsonToReg branch ----------
    t('JsonToReg branch is positioned BEFORE Restore branch and AFTER helpers', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      const idxConvertHelper = out.indexOf('function ConvertFrom-DoUndoJsonToReg');
      const idxJsonToReg     = out.search(/if \(\$JsonToReg\) \{/);
      const idxRestore       = out.search(/if \(\$Restore\) \{/);
      assert.ok(idxConvertHelper > 0 && idxJsonToReg > idxConvertHelper,
        'ConvertFrom-DoUndoJsonToReg must be defined before its `if ($JsonToReg)` invocation');
      assert.ok(idxRestore > idxJsonToReg,
        '`if ($JsonToReg)` must precede `if ($Restore)`');
    });


    t('default backup base is created under %ProgramData% with an Administrators-only ACL', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      assert.match(out, /Join-Path \$env:ProgramData 'Mozilla-SSLConfigGenerator'/);
      assert.match(out, /Initialize-BackupDirectory/);
      // Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18) only, no inheritance
      assert.match(out, /S-1-5-32-544/);
      assert.match(out, /S-1-5-18/);
      assert.match(out, /SetAccessRuleProtection\(\$true,\s*\$false\)/);
      // Path is printed to console
      assert.match(out, /Write-Host\s+"Backup base path:/);
    });

    // ---- L2: intent-revealing Set-Reg* helpers ----------------------------
    t('introduces Ensure-RegKey + Set-RegValue + Remove-RegValueIfPresent helpers', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      assert.match(out, /function Ensure-RegKey/);
      assert.match(out, /function Set-RegValue/);
      assert.match(out, /function Remove-RegValueIfPresent/);
      assert.match(out, /function Get-RegValueSnapshot/);
    });

    // ---- HSTS in do/undo (M1, requested as a follow-up requirement) -------
    t('HSTS is part of the DO-plan (Kind=WebConfig) so -Restore reverts it too', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', hsts: true }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // WebConfig helpers exist
      assert.match(out, /function Get-WebConfigSnapshot/);
      assert.match(out, /function Set-WebConfigValue/);
      // DO-plan contains a WebConfig entry for the <hsts> element. The
      // single quotes inside the filter literal are doubled by psQuote
      // (PowerShell single-quote escape), so the rendered text contains
      // ''Default Web Site'' (two pairs).
      assert.match(out, /Kind\s*=\s*'WebConfig'/);
      assert.match(out, /system\.applicationHost\/sites\/site\[@name=''Default Web Site''\]\/hsts/);
      // All four <hsts> attributes appear in the plan
      assert.match(out, /Name\s*=\s*'enabled'/);
      assert.match(out, /Name\s*=\s*'max-age'[^\n]*Value\s*=\s*63072000/);
      assert.match(out, /Name\s*=\s*'includeSubDomains'/);
      assert.match(out, /Name\s*=\s*'redirectHttpToHttps'/);
      // The snapshot/restore loops dispatch the WebConfig kind
      assert.match(out, /'WebConfig'\s*\{\s*Get-WebConfigSnapshot/);
      assert.match(out, /'WebConfig'\s*\{\s*Set-WebConfigValue/);
      // Strict-Transport-Security documentation comment still present
      assert.match(out, /Strict-Transport-Security:\s*max-age=63072000;\s*includeSubDomains/);
    });

    t('without form.hsts no WebConfig entries are emitted', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', hsts: false }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      assert.ok(!/Kind\s*=\s*'WebConfig'/.test(out), 'no WebConfig entries should be emitted without hsts');
      // The literal "Default Web Site" only appears in the DO-plan WebConfig
      // entries; the WebConfig helper-function bodies use generic
      // $PSPath/$Filter parameters (no hard-coded site name), so its absence
      // is a reliable signal that no HSTS planEntry was emitted.
      assert.ok(!/Default Web Site/.test(out), 'no Default Web Site filter without hsts');
    });

    // ---- H2: explicit DISABLE for protocols not in the requested set ------
    t('Modern profile: the DO-plan explicitly DISABLES TLS 1.0 / 1.1 / 1.2 (not just leaves them at OS defaults)', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', config: 'modern' }),
        makeOutput('modern', { cipherFormat: 'iana' }),
      );
      // For each legacy version, the DO-plan must contain Enabled=0 +
      // DisabledByDefault=1 for both Server and Client subkeys.
      ['TLS 1.0', 'TLS 1.1', 'TLS 1.2'].forEach(v => {
        const escV = v.replace(/\./g, '\\.');
        const reServerEnabled = new RegExp(`Protocols\\\\${escV}\\\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 0(?!\\d)`);
        const reClientEnabled = new RegExp(`Protocols\\\\${escV}\\\\Client'[^@]*?Name = 'Enabled'[^@]*?Value = 0(?!\\d)`);
        const reServerDbd     = new RegExp(`Protocols\\\\${escV}\\\\Server'[^@]*?Name = 'DisabledByDefault'[^@]*?Value = 1(?!\\d)`);
        assert.match(out, reServerEnabled, `Modern profile must DISABLE ${v} on Server (Enabled=0)`);
        assert.match(out, reClientEnabled, `Modern profile must DISABLE ${v} on Client (Enabled=0)`);
        assert.match(out, reServerDbd,     `Modern profile must set DisabledByDefault=1 for ${v} on Server`);
      });
      // And TLS 1.3 stays enabled.
      assert.match(out, /Protocols\\TLS 1\.3\\Server'[^@]*?Name = 'Enabled'[^@]*?Value = 4294967295/);
    });

    // ---- H1: Schannel cipher-suite allow-list ------------------------------
    t('intermediate: TLS_DHE_RSA_* tokens are dropped from Functions and a Write-Warning is emitted for each', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana' }),
      );
      // Functions value MUST NOT include any DHE_RSA suite (Schannel does not implement them).
      const funcMatch = out.match(/Name\s*=\s*'Functions'[^\n]*Value\s*=\s*'([^']+)'/);
      assert.ok(funcMatch, 'Functions REG_SZ value not found in DO-plan');
      const functionsValue = funcMatch[1];
      assert.ok(!/TLS_DHE_RSA_/.test(functionsValue),
        `Functions value must not contain TLS_DHE_RSA_*; got: ${functionsValue}`);
      // ECDHE suites that ARE implemented MUST be present.
      assert.ok(/TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256/.test(functionsValue));
      // Each dropped DHE token gets a runtime Write-Warning enumeration via $DroppedCiphers.
      assert.match(out, /\$DroppedCiphers\s*=\s*@\([^)]*'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'/);
      assert.match(out, /Write-Warning "Dropping cipher/);
      // And the comment header lists the dropped tokens for human inspection.
      assert.match(out, /NOT implemented by Schannel[\s\S]*TLS_DHE_RSA_WITH_AES_128_GCM_SHA256/);
    });

    t('TLS 1.3 advisory note is emitted whenever any TLS 1.3 cipher remains in Functions', () => {
      const out = iis(
        makeForm({ serverVersion: '10.0.26100', config: 'modern' }),
        // Modern profile in fixtures has empty .ciphers.iana — so push some
        // 1.3 suites in to exercise the advisory branch.
        makeOutput('modern', {
          cipherFormat: 'iana',
          ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
        }),
      );
      assert.match(out, /TLS 1\.3 cipher-suite ordering in Schannel is not user-tunable/);
    });

    // ---- L4: PQ assertions across all PQ modes -----------------------------
    PQ_MODES.forEach(mode => {
      t(`PQ mode='${mode}': renders correctly and surfaces MLKEM groups when present`, () => {
        const out = iis(
          makeForm({ serverVersion: '10.0.26100', config: 'modern', pq: mode }),
          makeOutput('modern', {
            cipherFormat: 'iana',
            pqMode: mode,
            supportsPq: true,
            tlsCurves: mode === 'none'
              ? ['X25519', 'prime256v1', 'secp384r1']
              : (mode === 'only'
                  ? ['X25519MLKEM768']
                  : ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1']),
          }),
        );
        if (mode === 'none') {
          // Classical only — no MLKEM string anywhere in EccCurves.
          const ec = out.match(/Name\s*=\s*'EccCurves'[^\n]*Value\s*=\s*@\(([^)]*)\)/);
          assert.ok(ec, 'EccCurves entry missing');
          assert.ok(!/MLKEM/.test(ec[1]), `mode=none must not surface MLKEM in EccCurves; got: ${ec[1]}`);
          assert.ok(!/PROVISIONAL/.test(out), 'mode=none should not emit the PQ provisional warning');
        }
        else {
          // Hybrid or only — MLKEM must surface in EccCurves AND a Write-Warning
          // about provisional Schannel string mappings must be emitted, AND the
          // header comment must include Get-TlsEccCurve verification instructions.
          assert.match(out, /'MLKEM768X25519'/);
          assert.match(out, /X25519MLKEM768/);
          assert.match(out, /PROVISIONAL/);
          assert.match(out, /Get-TlsEccCurve/);
          if (mode === 'only') {
            // Classical curves NOT requested; EccCurves should contain only MLKEM mapping.
            const ec = out.match(/Name\s*=\s*'EccCurves'[^\n]*Value\s*=\s*@\(([^)]*)\)/);
            assert.ok(/'MLKEM768X25519'/.test(ec[1]) && !/'curve25519'/.test(ec[1]),
              `mode=only EccCurves should be MLKEM-only; got: ${ec[1]}`);
          }
          else {
            // Hybrid — both MLKEM and classical curve25519 must appear.
            const ec = out.match(/Name\s*=\s*'EccCurves'[^\n]*Value\s*=\s*@\(([^)]*)\)/);
            assert.ok(/'MLKEM768X25519'/.test(ec[1]) && /'curve25519'/.test(ec[1]),
              `mode=mixed EccCurves should contain both MLKEM and classical; got: ${ec[1]}`);
          }
        }
      });
    });

    // ---- N1: psQuoteList escapes single quotes ----------------------------
    t("psQuoteList escapes embedded single quotes by doubling them", () => {
      // Inject an artificial token with a single quote into output.ciphers and
      // assert it survives quoting in the DroppedCiphers warning array (the
      // token is not in SCHANNEL_CIPHER_ALLOW so it ends up in $DroppedCiphers).
      const out = iis(
        makeForm({ serverVersion: '10.0.26100' }),
        makeOutput('intermediate', {
          cipherFormat: 'iana',
          ciphers: ["TLS_FAKE'INJECT_SUITE"],
        }),
      );
      // Should appear as 'TLS_FAKE''INJECT_SUITE' (PowerShell single-quote escape)
      assert.match(out, /'TLS_FAKE''INJECT_SUITE'/);
    });
  },
});
