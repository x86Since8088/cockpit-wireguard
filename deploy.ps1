<#
.SYNOPSIS
    Deploy the cockpit-wireguard WINDOWS CLIENT to this machine.

.DESCRIPTION
    The Cockpit plugin itself is Linux-only - Cockpit is - and deploy.sh is what
    installs it. What genuinely ships to Windows is windows-client\: the hook
    script WireGuard for Windows calls on PreUp/PostUp/PreDown/PostDown, and the
    two tunnel profiles. This script deploys exactly that, in the layout
    cockpit-secrets/source/docs/DEPLOY-CONTRACT.md section 1.2 defines:

        C:\Program Files\edt1-wg\payload\   the payload, replaced wholesale
        C:\ProgramData\edt1-wg\.env         operator config, seeded MISSING-ONLY
        C:\ProgramData\edt1-wg\state\       the undo journal; survives upgrade
        C:\ProgramData\edt1-wg\profiles\    the .conf files, for you to import

    WHY NO SYMLINKS HERE. mklink needs elevation or Developer Mode,
    SeCreateSymbolicLink is an audited privilege, and junctions behave
    differently under every backup and AV product on the estate. So Windows gets
    a copy, and the Windows equivalent of "in-place install" is simply that the
    hook script is RUN FROM payload\. (DEPLOY-CONTRACT.md JC-2. The cost is no
    live-edit dev install on Windows; the dev loop is re-running this script with
    -InstallTo.)

    WHY A SERVICE CAN NEVER WRITE payload\. Program Files is
    Administrators-writable only; ProgramData is where anything that must outlive
    an upgrade goes. A component that can rewrite its own executable is a
    persistence mechanism, not a component.

.PARAMETER InstallTo
    Override the install path. Absolute.

.PARAMETER Profile
    Which tunnel profile to place: split (default) or full.

.PARAMETER EnableHooks
    Set HKLM:\SOFTWARE\WireGuard\DangerousScriptExecution=1. WITHOUT THIS,
    WireGuard for Windows silently ignores every hook: the tunnel connects and
    the script never runs, with no warning anywhere. It is off by default here
    because the name is accurate - it lets ANY .conf you import run commands as
    SYSTEM - and turning that on is the operator's decision, not a deploy
    script's. Without the switch this script prints the exact command instead.

.PARAMETER Uninstall
    Remove payload\ and the profiles. Leaves C:\ProgramData\edt1-wg alone and
    says so.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 -EnableHooks
#>
[CmdletBinding()]
param(
    [string]$InstallTo = 'C:\Program Files\edt1-wg',
    [ValidateSet('split', 'full')][string]$Profile = 'split',
    [switch]$EnableHooks,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Self    = $MyInvocation.MyCommand.Path
$Src     = Join-Path (Split-Path -Parent $Self) 'windows-client'
$Project = 'edt1-wg'
$Data    = Join-Path $env:ProgramData $Project
$Payload = Join-Path $InstallTo 'payload'
$EnvFile = Join-Path $Data '.env'

# ---- the declaration. One list, same idea as install.sh's manifest block. ----
$PAYLOAD_FILES = @('wg-hooks.ps1')
$PROFILES      = @{ split = 'edt1-split.conf'; full = 'edt1-full.conf' }
$ENVDEFAULT    = '.envdefault'
$REQUIRED_ENV  = @('WG_TUNNEL_NAME', 'WG_UNDO_JOURNAL_DIR')

function Say  { param($m) Write-Host "  $m" }
function Warn { param($m) Write-Warning $m }
function Die  { param($m) Write-Error $m; exit 1 }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Die "must be run from an elevated PowerShell (Program Files is Administrators-writable only)"
    }
}

# The section 4.1 grammar. Deliberately the same subset the sh and python
# parsers accept, so one .env is read identically by all three.
function Read-EnvFile {
    param([string]$Path)
    $out = @{}
    $n = 0
    foreach ($raw in [IO.File]::ReadAllLines($Path)) {
        $n++
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        if ($line -notmatch '=') { Die "${Path}:${n}: not KEY=VALUE" }
        $k, $v = $line -split '=', 2
        $k = $k.Trim(); $v = $v.Trim()
        if ($k -notmatch '^[A-Z][A-Z0-9_]*$') { Die "${Path}:${n}: bad key '$k'" }
        if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
        if ($v -match '[\$`]') { Die "${Path}:${n}: $k contains `$ or backtick - interpolation is not supported (DEPLOY-CONTRACT.md 4.1)" }
        $out[$k] = $v
    }
    return $out
}

Assert-Admin

# ============================================================== uninstall =====

if ($Uninstall) {
    Write-Host "Uninstalling $Project"
    if (Test-Path $Payload) { Remove-Item -Recurse -Force -LiteralPath $Payload; Say "removed $Payload" }
    if ((Test-Path $InstallTo) -and -not (Get-ChildItem -Force -LiteralPath $InstallTo)) {
        Remove-Item -Force -LiteralPath $InstallTo; Say "removed empty $InstallTo"
    }
    Write-Host ""
    Write-Host "LEFT ALONE, deliberately:"
    Write-Host "  $Data      your .env, the undo journal and the profiles"
    Write-Host "  HKLM:\SOFTWARE\WireGuard\DangerousScriptExecution   (a system setting; clear it yourself if you want it off)"
    Write-Host "  Any tunnel you imported into WireGuard - this script never touched WireGuard's own store."
    exit 0
}

# ============================================================== pre-flight ====

Write-Host "Deploying $Project (Windows client)"
Say "from: $Src"
Say "to:   $Payload"
Write-Host ""
Write-Host "Pre-flight"

if (-not (Test-Path $Src)) { Die "no windows-client\ beside this script - run it from the checkout" }

$missing = @()
foreach ($f in $PAYLOAD_FILES) { if (-not (Test-Path (Join-Path $Src $f))) { $missing += $f } }
if (-not (Test-Path (Join-Path $Src $PROFILES[$Profile]))) { $missing += $PROFILES[$Profile] }
if (-not (Test-Path (Join-Path $Src $ENVDEFAULT)))         { $missing += $ENVDEFAULT }
if ($missing.Count) { Die ("payload is incomplete: " + ($missing -join ', ')) }
Say "1. payload complete"

# No dev root and no retired path in anything being shipped. Same check as
# install.sh's number 9, and for the same reason: a shipped file that hardcodes
# a share path is a file that breaks the moment the share is not mounted.
$bad = Select-String -Path (Get-ChildItem -LiteralPath $Src -File | ForEach-Object FullName) `
                     -Pattern '/opt/sc/git', 'ai-orchestrator-storage/projects' -SimpleMatch -ErrorAction SilentlyContinue
if ($bad) { $bad | ForEach-Object { Write-Host $_ }; Die "a shipped file hardcodes a dev or retired path. It belongs in .env." }
Say "2. no dev-root or retired path in any shipped file"

Write-Host "Pre-flight passed. Writing."
Write-Host ""

# ================================================================ the copy ====

New-Item -ItemType Directory -Force -Path $Payload, $Data, (Join-Path $Data 'state'), (Join-Path $Data 'profiles') | Out-Null

foreach ($f in $PAYLOAD_FILES) {
    Copy-Item -Force -LiteralPath (Join-Path $Src $f) -Destination (Join-Path $Payload $f)
    Say "installed $f"
}
$prof = $PROFILES[$Profile]
$profDest = Join-Path (Join-Path $Data 'profiles') $prof
if (Test-Path $profDest) {
    Say "kept existing $profDest (not overwritten - it may hold your PrivateKey)"
} else {
    Copy-Item -LiteralPath (Join-Path $Src $prof) -Destination $profDest
    Say "placed $profDest - edit the PrivateKey line, then import it in WireGuard"
}

# ================================================================ the .env ====

if (Test-Path $EnvFile) {
    Say "kept existing $EnvFile (not overwritten)"
    $have = (Read-EnvFile $EnvFile).Keys
    $want = (Read-EnvFile (Join-Path $Src $ENVDEFAULT)).Keys
    $new  = $want | Where-Object { $_ -notin $have }
    if ($new) { Warn ("this version adds keys your .env does not set: " + ($new -join ', ')) }
} else {
    Copy-Item -LiteralPath (Join-Path $Src $ENVDEFAULT) -Destination $EnvFile
    Say "seeded $EnvFile - REVIEW IT before first use"
}

$cfg = Read-EnvFile $EnvFile
foreach ($k in $REQUIRED_ENV) {
    if (-not $cfg.ContainsKey($k) -or $cfg[$k] -eq '') { Die "$EnvFile does not set $k" }
}
# A deployed .env carries locations and settings, never secrets.
foreach ($k in $cfg.Keys) {
    if ($k -match '(PASS|PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PASSPHRASE)' -and
        $k -notmatch '_(FILE|PATH|DIR|NAME|ID)$' -and $cfg[$k] -ne '') {
        Die "$k in $EnvFile looks like a secret VALUE. Put the material in a file and name the FILE here."
    }
}
Say ".env defines every required key and carries no secret-shaped value"

# ====================================================== the one system setting

$regPath = 'HKLM:\SOFTWARE\WireGuard'
$current = (Get-ItemProperty -Path $regPath -Name DangerousScriptExecution -ErrorAction SilentlyContinue).DangerousScriptExecution
if ($EnableHooks) {
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name DangerousScriptExecution -Value 1 -Type DWord
    Say "set DangerousScriptExecution=1 (you asked for it with -EnableHooks)"
    Say "restart the WireGuard service, or the running one keeps the old setting"
} elseif ($current -ne 1) {
    Write-Host ""
    Warn @"
Hooks are currently DISABLED, so wg-hooks.ps1 will never run: the tunnel will
connect and no PreUp/PostUp/PreDown/PostDown will fire, silently. To enable, from
an elevated PowerShell:

  New-Item -Path 'HKLM:\SOFTWARE\WireGuard' -Force | Out-Null
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\WireGuard' -Name 'DangerousScriptExecution' -Value 1 -Type DWord
  Restart-Service WireGuardManager

This is a machine-wide setting: it lets ANY tunnel config you import run commands
as SYSTEM. Only turn it on if you control every .conf on this machine. Re-run
this script with -EnableHooks to have it done for you.
"@
} else {
    Say "hooks already enabled (DangerousScriptExecution=1)"
}

# ====================================== no service, and no scheduled task =====
#
# Said out loud because its absence should not read as an oversight: this
# component has neither. WireGuard's own service invokes the hook script by
# path, so there is nothing here to register, nothing to start, and nothing for
# an uninstall to unregister. A deploy script that manufactured a task to look
# complete would be one more thing to fail.

Write-Host ""
Write-Host "Deployed."
Write-Host "  Hook script: $Payload\wg-hooks.ps1"
Write-Host "  Config:      $EnvFile"
Write-Host "  Profile:     $profDest"
Write-Host ""
Write-Host "  Next: put your client private key in the profile's [Interface] PrivateKey line,"
Write-Host "  import it in the WireGuard app, and point its hook lines at"
Write-Host "  $Payload\wg-hooks.ps1 ."
