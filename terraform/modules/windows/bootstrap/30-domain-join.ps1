# =============================================================================
# 30-domain-join.ps1
# Runs ONLY on WIN01 (member server).
#
# Phase A: wait for DC to be reachable, then domain-join. Reboots.
# Phase B: post-reboot - add bob to local Administrators, arm ART install task.
# =============================================================================

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\bootstrap-state'
$LogPath  = 'C:\bootstrap-member.log'
Start-Transcript -Path $LogPath -Append -Force | Out-Null
Write-Host "=== 30-domain-join.ps1 starting at $(Get-Date -Format o) ==="

$markerA = Join-Path $StateDir '30-joined.done'
$markerB = Join-Path $StateDir '30-postjoin.done'

# -----------------------------------------------------------------------------
# Phase A: domain join (pre-reboot)
# -----------------------------------------------------------------------------
if (-not (Test-Path $markerA)) {
    Write-Host "[A] Waiting for DC at $env:LAB_DC_IP to become reachable on TCP/389..."

    $deadline = (Get-Date).AddMinutes(20)  # DC promotion takes 8-12 min, plus reboot
    $reachable = $false
    while ((Get-Date) -lt $deadline) {
        $tnc = Test-NetConnection -ComputerName $env:LAB_DC_IP -Port 389 -WarningAction SilentlyContinue
        if ($tnc.TcpTestSucceeded) {
            $reachable = $true
            break
        }
        Write-Host "  DC not yet reachable, sleeping 30s..."
        Start-Sleep -Seconds 30
    }
    if (-not $reachable) { throw "DC at $env:LAB_DC_IP did not become reachable within 20 minutes" }

    # Point DNS at the DC so domain-join can resolve the SRV records
    Write-Host "[A] Setting DNS server to DC ($env:LAB_DC_IP)"
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $env:LAB_DC_IP

    # Brief settle
    Start-Sleep -Seconds 10

    # Schedule resume
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

    New-Item -ItemType File -Path $markerA -Force | Out-Null
    Add-Computer -DomainName $env:LAB_DOMAIN_NAME -Credential $cred -Restart -Force
    Stop-Transcript
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
    } catch {
        Write-Warning "Could not add bob to Administrators yet: $_  - will be retried on next boot"
    }

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
