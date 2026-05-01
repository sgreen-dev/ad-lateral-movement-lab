# =============================================================================
# 20-promote-dc.ps1
# Runs ONLY on DC01.
#
# Promotes the host to a domain controller for $env:LAB_DOMAIN_NAME,
# reboots once during promotion, then on the post-reboot run creates the
# test users (alice, bob, svc_backup).
#
# Idempotent: state markers track promotion phase. After full completion,
# subsequent invocations are no-ops.
# =============================================================================

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\bootstrap-state'
$LogPath  = 'C:\bootstrap-dc.log'
Start-Transcript -Path $LogPath -Append -Force | Out-Null
Write-Host "=== 20-promote-dc.ps1 starting at $(Get-Date -Format o) ==="

# -----------------------------------------------------------------------------
# Phase A: install AD DS role and promote (pre-reboot)
# -----------------------------------------------------------------------------
$markerA = Join-Path $StateDir '20-promote-initiated.done'
$markerB = Join-Path $StateDir '20-promote-complete.done'

if (-not (Test-Path $markerA)) {
    Write-Host "[A] Installing AD DS role"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

    Write-Host "[A] Setting local Administrator password from terraform-generated value"
    $localAdmin = Get-LocalUser -Name 'Administrator'
    $localAdmin | Set-LocalUser -Password (ConvertTo-SecureString $env:LAB_DOMAIN_ADMIN_PW -AsPlainText -Force)

    # Schedule a Run-on-startup task so we can resume after the promotion reboot
    $taskName = 'LabBootstrapResume'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File C:\bootstrap\20-promote-dc.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-Host "[A] Promoting to domain controller for $env:LAB_DOMAIN_NAME (this triggers reboot)"
    New-Item -ItemType File -Path $markerA -Force | Out-Null

    $dsrm = ConvertTo-SecureString $env:LAB_DSRM_PW -AsPlainText -Force
    Install-ADDSForest `
        -DomainName $env:LAB_DOMAIN_NAME `
        -DomainNetbiosName $env:LAB_DOMAIN_NETBIOS `
        -SafeModeAdministratorPassword $dsrm `
        -InstallDns:$true `
        -DomainMode 'WinThreshold' `
        -ForestMode 'WinThreshold' `
        -NoRebootOnCompletion:$false `
        -Force:$true

    # If we reach here without reboot (rare), exit and let scheduled task take over on next boot
    Stop-Transcript
    exit 0
}

# -----------------------------------------------------------------------------
# Phase B: post-promotion — create test users
# -----------------------------------------------------------------------------
if (-not (Test-Path $markerB)) {
    Write-Host "[B] Resuming after promotion reboot. Verifying AD readiness..."

    # Wait for AD DS to be fully ready (up to 5 min)
    $deadline = (Get-Date).AddMinutes(5)
    $adReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADDomain -ErrorAction Stop | Out-Null
            $adReady = $true
            break
        } catch {
            Start-Sleep -Seconds 10
        }
    }
    if (-not $adReady) { throw "AD did not become ready within 5 minutes" }

    Write-Host "[B] AD ready. Creating test users."

    $usersOu = "CN=Users,$((Get-ADDomain).DistinguishedName)"

    # alice — standard user
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'alice'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name 'alice' `
            -SamAccountName 'alice' `
            -UserPrincipalName "alice@$env:LAB_DOMAIN_NAME" `
            -GivenName 'Alice' -Surname 'Tester' `
            -DisplayName 'Alice Tester' `
            -AccountPassword (ConvertTo-SecureString $env:LAB_ALICE_PW -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Path $usersOu
        Write-Host "Created user alice"
    }

    # bob — will become local admin on WIN01 (added by member host's bootstrap)
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'bob'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name 'bob' `
            -SamAccountName 'bob' `
            -UserPrincipalName "bob@$env:LAB_DOMAIN_NAME" `
            -GivenName 'Bob' -Surname 'Admin' `
            -DisplayName 'Bob Admin' `
            -AccountPassword (ConvertTo-SecureString $env:LAB_BOB_PW -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Path $usersOu
        Write-Host "Created user bob"
    }

    # svc_backup — service account, victim of the WinRM lateral movement scenario
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_backup'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name 'svc_backup' `
            -SamAccountName 'svc_backup' `
            -UserPrincipalName "svc_backup@$env:LAB_DOMAIN_NAME" `
            -GivenName 'Backup' -Surname 'Service' `
            -DisplayName 'svc_backup' `
            -Description 'Lab service account — used for WinRM lateral movement emulation' `
            -AccountPassword (ConvertTo-SecureString $env:LAB_SVC_BACKUP_PW -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Path $usersOu
        Write-Host "Created user svc_backup"
    }

    # Make svc_backup a member of Remote Management Users so it can WinRM in
    Add-ADGroupMember -Identity 'Remote Management Users' -Members 'svc_backup' -ErrorAction SilentlyContinue

    # Clean up the resume scheduled task
    Unregister-ScheduledTask -TaskName 'LabBootstrapResume' -Confirm:$false -ErrorAction SilentlyContinue

    New-Item -ItemType File -Path $markerB -Force | Out-Null
    Write-Host "[B] DC bootstrap complete."
}

Write-Host "=== 20-promote-dc.ps1 done at $(Get-Date -Format o) ==="
Stop-Transcript
