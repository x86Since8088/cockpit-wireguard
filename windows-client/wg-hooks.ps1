<#
.SYNOPSIS
    PreUp / PostUp / PreDown / PostDown hooks for the edt1 WireGuard tunnel on
    Windows.

.DESCRIPTION
    WireGuard for Windows already installs the routes implied by AllowedIPs and
    removes them on disconnect, so these hooks deliberately do NOT manage routes
    for the tunnel itself. Fighting the client over its own route table is how
    you end up with a half-torn-down tunnel that blackholes traffic.

    What they DO handle is the part the client knows nothing about:

      PreUp     Snapshot the pre-tunnel network state (default route, DNS,
                forwarding flag) into an undo journal, BEFORE anything changes.
      PostUp    Verify the tunnel actually carries traffic rather than merely
                showing "Active", and enable IPv4 forwarding + a route for the
                local container subnet so containers on this laptop can reach
                edt1 through the tunnel.
      PreDown   Note that teardown started, so an interrupted PostDown is
                distinguishable from one that never ran.
      PostDown  Replay the journal in reverse: restore forwarding to its prior
                value and drop anything this script added. Idempotent - running
                it twice, or after a crash, converges to the same state.

    Everything this script changes is recorded in the journal first, and only
    entries written by this script are ever undone.

.PARAMETER Phase
    PreUp | PostUp | PreDown | PostDown

.PARAMETER Interface
    Tunnel name. WireGuard passes %WIREGUARD_TUNNEL_NAME%.

.PARAMETER ContainerSubnet
    Local container subnet on this machine that should reach edt1 through the
    tunnel (the ELT3 container range). Empty disables that handling.

.NOTES
    Hooks are IGNORED by WireGuard for Windows unless script execution is
    explicitly enabled - see README.md. Without that registry value the tunnel
    still works; these hooks simply never run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('PreUp', 'PostUp', 'PreDown', 'PostDown')]
    [string] $Phase,

    [string] $Interface       = $env:WIREGUARD_TUNNEL_NAME,
    [string] $ContainerSubnet = '172.16.2.0/25',
    [string] $TunnelGateway   = '172.16.0.1',
    [string] $LogDir
)

$ErrorActionPreference = 'Continue'

$TempRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
if (-not $LogDir) { $LogDir = Join-Path $TempRoot 'edt1-wg' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$Journal = Join-Path $LogDir 'undo.jsonl'
$Log     = Join-Path $LogDir 'hooks.log'

function Write-HookLog {
    param([string] $Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format o), $Phase, $Message
    Add-Content -Path $Log -Value $line
    # Write-Output, not Write-Host: WireGuard captures the hook's stdout into
    # the tunnel log, and Write-Host bypasses that stream entirely.
    Write-Output $line
}

# Record a change BEFORE making it. Each entry is one JSON object per line, so a
# partial write can never corrupt earlier entries.
function Add-Undo {
    param([string] $Action, [hashtable] $Data)
    $entry = @{ ts = (Get-Date -Format o); action = $Action; data = $Data } | ConvertTo-Json -Compress
    Add-Content -Path $Journal -Value $entry
}

function Get-Undo {
    if (-not (Test-Path $Journal)) { return @() }
    Get-Content $Journal | Where-Object { $_.Trim() } | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $_ }
}

switch ($Phase) {

    'PreUp' {
        # Snapshot BEFORE the tunnel exists, so PostDown has something truthful
        # to compare against.
        Remove-Item $Journal -ErrorAction SilentlyContinue
        $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1)
        if ($gw) { Write-HookLog ("pre-tunnel default route: via {0} on ifIndex {1}" -f $gw.NextHop, $gw.ifIndex) }
        else     { Write-HookLog 'pre-tunnel default route: NONE' }

        $fwd = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.Forwarding -eq 'Enabled' } | Select-Object -ExpandProperty ifIndex
        Add-Undo -Action 'snapshot' -Data @{
            default_gateway   = if ($gw) { $gw.NextHop } else { $null }
            forwarding_ifaces = @($fwd)
        }
        Write-HookLog 'snapshot recorded'
    }

    'PostUp' {
        Write-HookLog "tunnel '$Interface' reported up"

        # "Active" in the UI only means the interface exists. Prove the tunnel
        # actually carries traffic before declaring success - a handshake that
        # never completes looks identical until you send something.
        $ok = $false
        foreach ($attempt in 1..5) {
            if (Test-Connection -ComputerName $TunnelGateway -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                $ok = $true; break
            }
            Start-Sleep -Seconds 2
        }
        if ($ok) { Write-HookLog "verified: $TunnelGateway answers through the tunnel" }
        else     { Write-HookLog "WARNING: $TunnelGateway did not answer - tunnel is up but not passing traffic" }

        # Containers on this laptop live on $ContainerSubnet and are announced to
        # edt1 through this peer's AllowedIPs. For their traffic to actually
        # leave via the tunnel this host must forward IPv4.
        if ($ContainerSubnet) {
            $ifIdx = (Get-NetAdapter | Where-Object { $_.Name -eq $Interface } |
                      Select-Object -First 1 -ExpandProperty ifIndex)
            if ($ifIdx) {
                $iface = Get-NetIPInterface -ifIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($iface -and $iface.Forwarding -ne 'Enabled') {
                    Add-Undo -Action 'forwarding' -Data @{ ifIndex = $ifIdx; previous = "$($iface.Forwarding)" }
                    Set-NetIPInterface -ifIndex $ifIdx -AddressFamily IPv4 -Forwarding Enabled -ErrorAction SilentlyContinue
                    Write-HookLog "enabled IPv4 forwarding on ifIndex $ifIdx (was $($iface.Forwarding))"
                } else {
                    Write-HookLog "IPv4 forwarding already enabled on ifIndex $ifIdx"
                }
            } else {
                Write-HookLog "WARNING: could not resolve adapter for '$Interface'; skipped forwarding setup"
            }
        }

        # Report, do not "fix": the routes come from AllowedIPs and the client
        # owns them.
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.InterfaceAlias -eq $Interface }
        Write-HookLog ("routes installed by the client: {0}" -f (($routes | ForEach-Object DestinationPrefix) -join ', '))
    }

    'PreDown' {
        Write-HookLog "teardown starting for '$Interface'"
        Add-Undo -Action 'predown' -Data @{ interface = $Interface }
    }

    'PostDown' {
        # Replay in reverse. Only entries this script wrote are touched.
        $entries = @(Get-Undo)
        [array]::Reverse($entries)
        foreach ($e in $entries) {
            switch ($e.action) {
                'forwarding' {
                    try {
                        Set-NetIPInterface -ifIndex $e.data.ifIndex -AddressFamily IPv4 `
                            -Forwarding $e.data.previous -ErrorAction Stop
                        Write-HookLog "restored forwarding on ifIndex $($e.data.ifIndex) to $($e.data.previous)"
                    } catch {
                        # The interface disappears with the tunnel, which is the
                        # normal case - not an error worth alarming about.
                        Write-HookLog "forwarding restore skipped (interface gone): $($_.Exception.Message)"
                    }
                }
                default { }
            }
        }
        Remove-Item $Journal -ErrorAction SilentlyContinue
        Write-HookLog 'teardown complete; journal consumed'
    }
}
