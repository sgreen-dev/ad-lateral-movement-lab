# =============================================================================
# 30-domain-join.ps1
# Runs ONLY on WIN01 (member server).
#
# Phase A: wait for DC to be reachable, then domain-join. Reboots.
# Phase B: post-reboot - add bob to local Administrators, arm ART install task.
# =============================================================================

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\bootstrap-state'
$LogPath = 'C:\bootstrap-member.log'
Start-Transcript -Path $LogPath -Append -Force | Out-Null
Write-Host "=== 30-domain-join.ps1 starting at $(Get-Date -Format o) ==="

# Fail-loud guards: refuse to run with missing inputs rather than
# producing a misleading "domain does not exist" error 10 minutes later.
foreach ($required in @('LAB_DC_IP', 'LAB_DOMAIN_NAME', 'LAB_DOMAIN_NETBIOS', 'LAB_DOMAIN_ADMIN_PW')) {
    if (-not (Get-Item "env:$required" -ErrorAction SilentlyContinue).Value) {
        throw "Required environment variable $required is empty or unset"
    }
}

$markerA = Join-Path $StateDir '30-joined.done'
$markerB = Join-Path $StateDir '30-postjoin.done'

# -----------------------------------------------------------------------------
# Phase A: domain join (pre-reboot)
# -----------------------------------------------------------------------------
if (-not (Test-Path $markerA)) {

    # Point DNS at the DC FIRST so SRV-record resolution can succeed
    Write-Host "[A] Setting DNS server to DC ($env:LAB_DC_IP)"
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $env:LAB_DC_IP

    # Wait for the domain to be JOIN-READY, not just for LDAP to be listening.
    # _ldap._tcp.dc._msdcs.<domain> is the SRV record Add-Computer uses to
    # discover a DC; it is only registered once Netlogon is fully up and the
    # directory is integrated with DNS. This is the right probe.
    Write-Host "[A] Waiting for $env:LAB_DOMAIN_NAME to be join-ready (SRV records)..."
    $deadline = (Get-Date).AddMinutes(20)  # DC promotion takes 8-12 min, plus reboot
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $srv = Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.$env:LAB_DOMAIN_NAME" -Server $env:LAB_DC_IP -ErrorAction Stop
            if ($srv) {
                $ready = $true
                Write-Host "  SRV records present - domain is join-ready"
                break
            }
        }
        catch {
            Write-Host "  Domain not yet join-ready, sleeping 30s..."
            Start-Sleep -Seconds 30
        }
    }
    if (-not $ready) { throw "Domain $env:LAB_DOMAIN_NAME did not become join-ready within 20 minutes" }

    # Schedule resume so Phase B runs after the reboot triggered by Add-Computer
    $taskName = 'LabBootstrapResume'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File C:\bootstrap\30-domain-join.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-Host "[A] Joining domain $env:LAB_DOMAIN_NAME"
    $cred = New-Object System.Management.Automation.PSCredential(
        "$env:LAB_DOMAIN_NETBIOS\Administrator",
        (ConvertTo-SecureString $env:LAB_DOMAIN_ADMIN_PW -AsPlainText -Force)
    )

    # NOTE: marker is created AFTER the join succeeds, not before. If the join
    # fails, the resume task will retry Phase A on next boot.
    Add-Computer -DomainName $env:LAB_DOMAIN_NAME -Credential $cred -Force
    New-Item -ItemType File -Path $markerA -Force | Out-Null

    Write-Host "[A] Join succeeded - restarting"
    Stop-Transcript
    Restart-Computer -Force
    exit 0
}

# -----------------------------------------------------------------------------
# Phase B: post-join - local admin assignment + ART install
# -----------------------------------------------------------------------------
if (-not (Test-Path $markerB)) {
    Write-Host "[B] Post-join. Adding $env:LAB_DOMAIN_NETBIOS\bob to local Administrators."

    # Wait for the machine's domain context to settle
    Start-Sleep -Seconds 15

    try {
        $alreadyMember = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "$env:LAB_DOMAIN_NETBIOS\bob" }); if (-not $alreadyMember) { Add-LocalGroupMember -Group 'Administrators' -Member "$env:LAB_DOMAIN_NETBIOS\bob" -ErrorAction Stop }
        Write-Host "Added $env:LAB_DOMAIN_NETBIOS\bob to local Administrators"
    }
    catch {
        Write-Warning "Could not add bob to Administrators yet: $_  - will be retried on next boot"
    }

    # Enable SMB inbound (TCP 445) so SMB-based lateral movement (T1021.002) can
    # reach this host. Server 2022 blocks File and Printer Sharing by default.
    # Scoped to the single SMB-In rule (by stable -Name, not display name) rather
    # than the whole group, to keep attacker-facing surface minimal.
    Write-Host "[B] Enabling File and Printer Sharing (SMB-In) firewall rule"
    Enable-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction SilentlyContinue

    # Run the ART installer immediately rather than scheduling - we're already post-reboot
    $artScript = 'C:\bootstrap\40-install-art.ps1'
    if (Test-Path $artScript) {
        Write-Host "[B] Running ART installer"
        & $artScript
    }

    Unregister-ScheduledTask -TaskName 'LabBootstrapResume' -Confirm:$false -ErrorAction SilentlyContinue
    New-Item -ItemType File -Path $markerB -Force | Out-Null
    Write-Host "[B] Member bootstrap complete."
}

Write-Host "=== 30-domain-join.ps1 done at $(Get-Date -Format o) ==="
Stop-Transcript