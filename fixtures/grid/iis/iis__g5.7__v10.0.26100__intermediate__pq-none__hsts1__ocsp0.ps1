# generated 1970-01-01, Mozilla Guideline v5.7, IIS (PowerShell) 10.0.26100, intermediate config, PQ: none, HSTS
# https://ssl-config.mozilla.org/#server=iis&version=10.0.26100&config=intermediate&guideline=5.7&hsts=true&ocsp=false&pq=none
#
# Save this file as Set-IISTls.ps1 and run it from an ELEVATED PowerShell
# prompt (Run as Administrator). The script edits Schannel registry keys
# that are read by every TLS consumer on the box (IIS, .NET, WinHTTP,
# RDP, SMB, ...), so the changes apply system-wide.
#
# Usage:
#   .\Set-IISTls.ps1                              # snapshot current state, then apply
#   .\Set-IISTls.ps1 -BackupPath C:\path\backup    # custom backup base path
#   .\Set-IISTls.ps1 -Restore -BackupPath C:\path\backup   # roll back from <base>.undo.json
#   .\Set-IISTls.ps1 -JsonToReg C:\path\backup.do.json [-RegOut out.reg]
#                                                  # convert a do/undo JSON snapshot to a
#                                                  # Windows Registry Editor v5 (.reg) file.
#                                                  # Read-only; does not require Administrator.
#
# Schannel protocol / cipher / group changes require a REBOOT to take effect.
#
# Mozilla profile groups -> Schannel names:
#   X25519 -> curve25519
#   prime256v1 -> NistP256
#   secp384r1 -> NistP384
#
# NOTE: the following IANA cipher-suite names from the Mozilla profile
# are NOT implemented by Schannel and have been dropped from the
# Functions value (the script will also Write-Warning at runtime):
#   - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
#   - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
#   - TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

[CmdletBinding()]
param(
    [switch]$Restore,
    [string]$BackupPath,
    # Read-only conversion of a do.json / undo.json snapshot into a
    # Windows Registry Editor v5 (.reg) file. Does NOT modify the host.
    [string]$JsonToReg,
    [string]$RegOut
)

$ErrorActionPreference = 'Stop'

# Require Administrator: every key written below lives under HKLM.
# (Skipped for -JsonToReg: that path performs only a read of the JSON
# snapshot and writes a .reg file, no HKLM mutation.)
if (-not $JsonToReg) {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Set-IISTls.ps1 must be run from an elevated PowerShell prompt (Administrator).'
    }
}

# ---------------------------------------------------------------------------
# L1 + file-ACL hardening: default backup base path is under %ProgramData%
# in a directory we create with an Administrators+SYSTEM-only ACL, so a
# non-admin process cannot pre-create a reparse point at the snapshot
# location nor read the snapshot files (which describe the host's pre-
# apply Schannel state — useful intelligence for an attacker scoping a
# downgrade attack). The same ACL is applied to the do.json / undo.json
# files themselves immediately after they are written.
# ---------------------------------------------------------------------------
function New-AdminOnlyAcl {
    param([Parameter(Mandatory)][ValidateSet('Directory','File')][string]$Kind)
    if ($Kind -eq 'Directory') {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inherit = [System.Security.AccessControl.InheritanceFlags]::"ContainerInherit, ObjectInherit"
    }
    else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop inherited
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $prop   = [System.Security.AccessControl.PropagationFlags]::None
    $allow  = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @('S-1-5-32-544','S-1-5-18')) {  # Administrators, SYSTEM
        $id = (New-Object System.Security.Principal.SecurityIdentifier $sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule $id,$rights,$inherit,$prop,$allow))
    }
    return $acl
}
function Initialize-BackupDirectory {
    [CmdletBinding()] param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        # Refuse to use a path that is a file or a reparse point —
        # otherwise an attacker could pre-create a junction at our
        # default %ProgramData% location aimed at e.g. C:\Windows.
        $existing = Get-Item -LiteralPath $Path -Force
        if (-not $existing.PSIsContainer) {
            throw "Backup path $Path exists but is not a directory."
        }
        if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            throw "Backup path $Path is a reparse point/junction; refusing to use it."
        }
    }
    else {
        $null = New-Item -Path $Path -ItemType Directory -Force
    }
    # Always (re-)apply the Administrators+SYSTEM-only ACL so an existing
    # but loosely-permissioned directory gets locked down too.
    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind Directory)
}
function Protect-File {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Protect-File: file does not exist: $Path"
    }
    $f = Get-Item -LiteralPath $Path -Force
    if ($f.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
        throw "Protect-File: refusing to ACL a reparse point: $Path"
    }
    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind File)
}
function New-ProtectedFile {
    # Create an EMPTY file with the strict Administrators+SYSTEM ACL
    # BEFORE any content is written. The previous "Set-Content first,
    # Protect-File after" sequence created the file with the parent
    # directory's ACL — fine for the default %ProgramData% location
    # (locked down by Initialize-BackupDirectory) but NOT for a
    # caller-supplied -BackupPath under e.g. C:\Temp, where the file
    # would briefly hold sensitive snapshot content with a permissive
    # inherited ACL between the Set-Content write and the Set-Acl tighten.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Item -LiteralPath $Path -Force
        if ($existing.PSIsContainer) {
            throw "New-ProtectedFile: $Path exists and is a directory."
        }
        if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            throw "New-ProtectedFile: $Path exists and is a reparse point/symlink; refusing to use it."
        }
        # Pre-existing file: truncate via FileMode::Create (CreateNew
        # would throw if the file exists; Truncate would throw if it
        # does not). The handle is closed immediately — Set-Content
        # below opens its own handle.
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $fs.Close()
    }
    else {
        # Atomic create-or-fail: FileMode::CreateNew defeats a TOCTOU
        # race where an attacker plants a symlink between our
        # Test-Path check and our open call.
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $fs.Close()
    }
    # Tighten the ACL while the file is still empty.
    Set-Acl -Path $Path -AclObject (New-AdminOnlyAcl -Kind File)
}

# ---------------------------------------------------------------------------
# -JsonToReg: read a do.json or undo.json snapshot and emit a Windows
# Registry Editor v5 (.reg) file. This is a read-only operation that
# does NOT modify the host, so it runs BEFORE the elevation check (a
# non-admin can convert JSON -> .reg for inspection / staging). The
# emitted .reg file is ACL-protected with the same Administrators+SYSTEM
# ACL as the source JSON to avoid leaking the host's pre-apply state.
#
# Mapping:
#   Kind=Registry, Existed=$true, Type=DWord       -> "Name"=dword:XXXXXXXX
#   Kind=Registry, Existed=$true, Type=String      -> "Name"="..."
#   Kind=Registry, Existed=$true, Type=MultiString -> "Name"=hex(7):...   (UTF-16LE)
#   Kind=Registry, Existed=$false                  -> "Name"=-            (delete-value)
#   Kind=WebConfig                                 -> ; comment (.reg cannot express IIS web-config)
# ---------------------------------------------------------------------------
function ConvertTo-RegStringLiteral {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    # .reg v5 string escapes: backslash and double-quote are doubled by
    # backslash; everything else is literal (including non-ASCII, which
    # the .reg file is UTF-16LE BOM-prefixed to support).
    return '"' + ($Value -replace '\\','\\\\' -replace '"','\\"') + '"'
}
function ConvertTo-RegMultiStringHex {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Values)
    # REG_MULTI_SZ in .reg files is hex(7) of UTF-16LE-encoded strings
    # each terminated by a U+0000, with a final extra U+0000 terminator.
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($s in $Values) {
        $b = [System.Text.Encoding]::Unicode.GetBytes($s)
        $bytes.AddRange($b)
        $bytes.Add(0); $bytes.Add(0)  # U+0000 terminator for this string
    }
    $bytes.Add(0); $bytes.Add(0)      # final U+0000 terminator for the list
    return 'hex(7):' + (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
}
function ConvertFrom-DoUndoJsonToReg {
    param([Parameter(Mandatory)][string]$JsonPath,
          [Parameter(Mandatory)][string]$RegPath)
    if (-not (Test-Path -LiteralPath $JsonPath)) {
        throw "JsonToReg: input JSON not found: $JsonPath"
    }
    $entries = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    # Group Registry entries by Path to emit one [Key] block each.
    $regEntries = @($entries | Where-Object { $_.Kind -eq 'Registry' })
    $webEntries = @($entries | Where-Object { $_.Kind -eq 'WebConfig' })
    $byPath = @{}
    foreach ($e in $regEntries) {
        if (-not $byPath.ContainsKey($e.Path)) { $byPath[$e.Path] = New-Object System.Collections.ArrayList }
        $null = $byPath[$e.Path].Add($e)
    }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('Windows Registry Editor Version 5.00')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('; Generated from ' + $JsonPath)
    $null = $sb.AppendLine('; NOTE: Importing a .reg file APPENDS values; it cannot DELETE values')
    $null = $sb.AppendLine(';       that did not exist before (those appear below as "Name"=- entries')
    $null = $sb.AppendLine(';       which DO delete on import). For full fidelity, prefer')
    $null = $sb.AppendLine(';       `.\\Set-IISTls.ps1 -Restore -BackupPath ...` over `reg import`.')
    $null = $sb.AppendLine('')
    foreach ($p in $byPath.Keys) {
        # .reg uses the long-form HKEY_LOCAL_MACHINE prefix. Note: this
        # local is named $regKey (NOT $regPath) because PowerShell
        # variables are case-insensitive and $RegPath is the function
        # parameter — assigning to $regPath here would silently clobber
        # the output path, causing WriteAllText below to write to the
        # last key name instead of the requested .reg file.
        $regKey = $p -replace '^HKLM\\','HKEY_LOCAL_MACHINE\' `
                     -replace '^HKCU\\','HKEY_CURRENT_USER\'
        $null = $sb.AppendLine('[' + $regKey + ']')
        foreach ($e in $byPath[$p]) {
            $name = ConvertTo-RegStringLiteral -Value $e.Name
            if (-not $e.Existed) {
                $null = $sb.AppendLine($name + '=-')
                continue
            }
            switch ($e.Type) {
                'DWord' {
                    # Coerce via [uint32] to render the unsigned 32-bit value.
                    $u = [uint32]([int64]$e.Value -band 0xFFFFFFFF)
                    $null = $sb.AppendLine($name + '=dword:' + ('{0:x8}' -f $u))
                }
                'String' {
                    $null = $sb.AppendLine($name + '=' + (ConvertTo-RegStringLiteral -Value ([string]$e.Value)))
                }
                'MultiString' {
                    # ConvertFrom-Json gives an Object[]; coerce to string[].
                    $arr = @($e.Value | ForEach-Object { [string]$_ })
                    $null = $sb.AppendLine($name + '=' + (ConvertTo-RegMultiStringHex -Values $arr))
                }
                default {
                    $null = $sb.AppendLine('; UNSUPPORTED Type=' + $e.Type + ' for ' + $name)
                }
            }
        }
        $null = $sb.AppendLine('')
    }
    if ($webEntries.Count -gt 0) {
        $null = $sb.AppendLine('; --- WebConfig entries (NOT representable in a .reg file) ---')
        $null = $sb.AppendLine('; The following IIS web-configuration entries from the snapshot cannot')
        $null = $sb.AppendLine('; be expressed in .reg syntax. Use Set-WebConfigurationProperty in')
        $null = $sb.AppendLine('; PowerShell (or `.\\Set-IISTls.ps1 -Restore`) to apply them:')
        foreach ($e in $webEntries) {
            $null = $sb.AppendLine(';   Filter=' + $e.Filter + '  Name=' + $e.Name + '  Value=' + $e.Value)
        }
    }
    # .reg files MUST be UTF-16LE with a BOM, otherwise reg.exe will
    # reject the file or mangle non-ASCII string values. Open the
    # PRE-EXISTING (caller-protected) file with Truncate so the file
    # ACL set by New-ProtectedFile is preserved (vs. WriteAllText
    # which creates the file with the parent's inherited ACL on miss).
    $utf16 = New-Object System.Text.UnicodeEncoding($false, $true)  # LE, BOM
    if (-not (Test-Path -LiteralPath $RegPath)) {
        throw "ConvertFrom-DoUndoJsonToReg: output file must be pre-created (and ACL-protected) by the caller: $RegPath"
    }
    $fs = [System.IO.File]::Open($RegPath, [System.IO.FileMode]::Truncate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $sw = New-Object System.IO.StreamWriter($fs, $utf16)
        $sw.Write($sb.ToString())
        $sw.Flush()
        $sw.Close()
    }
    finally { $fs.Dispose() }
}

if ($JsonToReg) {
    if (-not $RegOut) {
        # Default: same base name, .reg extension.
        $RegOut = [System.IO.Path]::ChangeExtension($JsonToReg, '.reg')
        # Strip the .do/.undo infix from the stem so foo.undo.json -> foo.reg.
        $RegOut = $RegOut -replace '\.(do|undo)\.reg$','.reg'
    }
    # Pre-create with strict ACL BEFORE writing the .reg payload
    # (the snapshot may describe sensitive Schannel state — same
    # reasoning as for .do.json / .undo.json above).
    New-ProtectedFile -Path $RegOut
    ConvertFrom-DoUndoJsonToReg -JsonPath $JsonToReg -RegPath $RegOut
    Write-Host "Wrote .reg file: $RegOut"
    Write-Host 'NOTE: `reg import` cannot DELETE registry values; for fidelity use'
    Write-Host '      `.\Set-IISTls.ps1 -Restore -BackupPath <base>` instead.'
    return
}

if (-not $BackupPath) {
    $backupDir = Join-Path $env:ProgramData 'Mozilla-SSLConfigGenerator'
    Initialize-BackupDirectory -Path $backupDir
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupPath = Join-Path $backupDir ("schannel-backup-{0}" -f $stamp)
}
Write-Host "Backup base path: $BackupPath"
Write-Host "  (do-plan: ${BackupPath}.do.json   undo-snapshot: ${BackupPath}.undo.json)"

$SchannelBase = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$CipherKey    = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'

# ---------------------------------------------------------------------------
# L2: tiny, intent-revealing helpers wrapping the Test-Path / New-Item /
# New-ItemProperty dance. All registry mutations go through Set-Reg* so
# the snapshot / replay logic only has to know one shape of operation.
# ---------------------------------------------------------------------------
function Ensure-RegKey {
    param([Parameter(Mandatory)][string]$Path)
    $literal = "Registry::$Path"
    if (-not (Test-Path -LiteralPath $literal)) { $null = New-Item -Path $literal -Force }
}
function Get-RegValueSnapshot {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$Name)
    $literal = "Registry::$Path"
    if (-not (Test-Path -LiteralPath $literal)) {
        return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$false; Type=$null; Value=$null }
    }
    $key = Get-Item -LiteralPath $literal
    if ($null -eq $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')) {
        # Distinguish "value missing" from "value present but $null":
        # property names list is authoritative.
        if ($key.Property -notcontains $Name) {
            return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$false; Type=$null; Value=$null }
        }
    }
    $type  = $key.GetValueKind($Name).ToString()
    $value = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
    return [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$true; Type=$type; Value=$value }
}
function Set-RegValue {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][ValidateSet('DWord','String','MultiString')][string]$Type,
          [Parameter(Mandatory)]$Value)
    Ensure-RegKey -Path $Path
    $null = New-ItemProperty -Path "Registry::$Path" -Name $Name -Value $Value -PropertyType $Type -Force
}
function Remove-RegValueIfPresent {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$Name)
    $literal = "Registry::$Path"
    if (Test-Path -LiteralPath $literal) {
        $key = Get-Item -LiteralPath $literal
        if ($key.Property -contains $Name) {
            Remove-ItemProperty -LiteralPath $literal -Name $Name -Force
        }
    }
}

# ---------------------------------------------------------------------------
# IIS web-configuration helpers (HSTS lives at
# system.applicationHost/sites/site[@name=...]/hsts in applicationHost.config).
# Snapshot returns the current value of a single property; on -Restore we
# write it back. The <hsts> element always exists at the section level
# (with default values) so Existed is always $true for WebConfig entries.
# ---------------------------------------------------------------------------
function Get-WebConfigSnapshot {
    param([Parameter(Mandatory)][string]$PSPath,
          [Parameter(Mandatory)][string]$Filter,
          [Parameter(Mandatory)][string]$Name)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $current = $null
    try {
        $prop = Get-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name -ErrorAction Stop
        if ($null -ne $prop) {
            # Get-WebConfigurationProperty returns either a primitive or a
            # ConfigurationAttribute with a .Value property — normalise.
            if ($prop.PSObject.Properties['Value']) { $current = $prop.Value } else { $current = $prop }
        }
    }
    catch { $current = $null }
    return [pscustomobject]@{ PSPath=$PSPath; Filter=$Filter; Name=$Name; Existed=$true; Value=$current }
}
function Set-WebConfigValue {
    param([Parameter(Mandatory)][string]$PSPath,
          [Parameter(Mandatory)][string]$Filter,
          [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)]$Value)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name -Value $Value
}

# ---------------------------------------------------------------------------
# -Restore: read the undo-snapshot JSON and reverse every recorded change.
# Values that did NOT exist before are deleted; values that did exist are
# restored to their previous Type + Value (this is what `reg.exe import`
# could NOT do — it cannot remove keys/values created since the export).
# ---------------------------------------------------------------------------
if ($Restore) {
    $undoFile = "${BackupPath}.undo.json"
    if (-not (Test-Path -LiteralPath $undoFile)) {
        throw "Undo snapshot not found: $undoFile"
    }
    Write-Host "Restoring SCHANNEL + IIS settings from $undoFile ..."
    $entries = Get-Content -LiteralPath $undoFile -Raw | ConvertFrom-Json
    foreach ($e in $entries) {
        switch ($e.Kind) {
            'Registry' {
                if ($e.Existed) {
                    Set-RegValue -Path $e.Path -Name $e.Name -Type $e.Type -Value $e.Value
                }
                else {
                    Remove-RegValueIfPresent -Path $e.Path -Name $e.Name
                }
            }
            'WebConfig' {
                # <hsts> properties always have defaults; just write the captured value back.
                Set-WebConfigValue -PSPath $e.PSPath -Filter $e.Filter -Name $e.Name -Value $e.Value
            }
            default { throw "Unknown undo entry Kind: $($e.Kind)" }
        }
    }
    Write-Host 'A reboot is required for Schannel changes to take effect.'
    return
}

# ===========================================================================
# Apply pass.
# ===========================================================================

# ---------------------------------------------------------------------------
# DO-plan — every registry mutation we are about to perform, in order.
# The corresponding undo-snapshot is captured BEFORE any mutation so it
# always reflects the pre-apply state of the host.
# ---------------------------------------------------------------------------
$DoPlan = @(
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; Name = 'Enabled'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; Name = 'Enabled'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; Name = 'Enabled'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; Name = 'Enabled'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'; Name = 'Enabled'; Type = 'DWord'; Value = 4294967295 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'; Name = 'Enabled'; Type = 'DWord'; Value = 4294967295 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; Name = 'Enabled'; Type = 'DWord'; Value = 4294967295 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; Name = 'Enabled'; Type = 'DWord'; Value = 4294967295 },
    @{ Kind = 'Registry'; Path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 },
    @{ Kind = 'Registry'; Path = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'; Name = 'Functions'; Type = 'String'; Value = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256' },
    @{ Kind = 'Registry'; Path = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'; Name = 'EccCurves'; Type = 'MultiString'; Value = @('curve25519', 'NistP256', 'NistP384') },
    @{ Kind = 'WebConfig'; PSPath = 'MACHINE/WEBROOT/APPHOST'; Filter = 'system.applicationHost/sites/site[@name=''Default Web Site'']/hsts'; Name = 'enabled'; Value = $true },
    @{ Kind = 'WebConfig'; PSPath = 'MACHINE/WEBROOT/APPHOST'; Filter = 'system.applicationHost/sites/site[@name=''Default Web Site'']/hsts'; Name = 'max-age'; Value = 63072000 },
    @{ Kind = 'WebConfig'; PSPath = 'MACHINE/WEBROOT/APPHOST'; Filter = 'system.applicationHost/sites/site[@name=''Default Web Site'']/hsts'; Name = 'includeSubDomains'; Value = $true },
    @{ Kind = 'WebConfig'; PSPath = 'MACHINE/WEBROOT/APPHOST'; Filter = 'system.applicationHost/sites/site[@name=''Default Web Site'']/hsts'; Name = 'redirectHttpToHttps'; Value = $true }
)

# Capture the pre-apply state of every entry mentioned in the DO-plan.
$Undo = foreach ($op in $DoPlan) {
    switch ($op.Kind) {
        'Registry'  { Get-RegValueSnapshot -Path $op.Path -Name $op.Name }
        'WebConfig' { Get-WebConfigSnapshot -PSPath $op.PSPath -Filter $op.Filter -Name $op.Name }
        default     { throw "Unknown DO-plan entry Kind: $($op.Kind)" }
    }
}

# Persist DO-plan and UNDO-snapshot. Pre-create each file with the
# strict Administrators+SYSTEM ACL FIRST, then Set-Content overwrites
# the (empty) file — file ACLs are preserved across Set-Content writes
# to an existing file, so the snapshot data never lands on disk under
# the parent directory's (potentially permissive) inherited ACL.
New-ProtectedFile -Path ("${BackupPath}.do.json")
$DoPlan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ("${BackupPath}.do.json")   -Encoding UTF8
New-ProtectedFile -Path ("${BackupPath}.undo.json")
$Undo   | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ("${BackupPath}.undo.json") -Encoding UTF8
Write-Host "DO-plan written to ${BackupPath}.do.json ("$DoPlan.Count" entries)"
Write-Host "UNDO snapshot written to ${BackupPath}.undo.json"

# H1: dropped IANA cipher-suite names that Schannel does not implement.
$DroppedCiphers = @('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256')
foreach ($c in $DroppedCiphers) {
    Write-Warning "Dropping cipher '$c' — not implemented by Schannel; not written to Functions."
}

# ---------------------------------------------------------------------------
# Apply the DO-plan (registry writes + IIS <hsts> writes alike).
# ---------------------------------------------------------------------------
foreach ($op in $DoPlan) {
    switch ($op.Kind) {
        'Registry'  { Set-RegValue -Path $op.Path -Name $op.Name -Type $op.Type -Value $op.Value }
        'WebConfig' { Set-WebConfigValue -PSPath $op.PSPath -Filter $op.Filter -Name $op.Name -Value $op.Value }
        default     { throw "Unknown DO-plan entry Kind: $($op.Kind)" }
    }
}

# Note: the protocol DO-plan above EXPLICITLY disables every TLS version
# in ["TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3"] that is not in
# the Mozilla intermediate profile, by writing
# Enabled=0 / DisabledByDefault=1 under HKLM\...\SCHANNEL\Protocols\<name>\Server
# and \Client. This is intentional — the previous "leave at OS defaults"
# behaviour silently kept TLS 1.0 / 1.1 enabled on Server 2019/2022.

# HSTS (IIS 10 v1709+ native <hsts> element under "Default Web Site"):
#   max-age=63072000; includeSubDomains; redirectHttpToHttps=true.
# Strict-Transport-Security: max-age=63072000; includeSubDomains
# Adjust the site name in the DO-plan WebConfig entries above if you are
# not configuring "Default Web Site".

Write-Host ''
Write-Host 'Done. A REBOOT is required for Schannel protocol/cipher/group changes to take effect.'
Write-Host "To revert, run:  .\Set-IISTls.ps1 -Restore -BackupPath '$BackupPath'"
