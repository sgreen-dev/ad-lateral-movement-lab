# =============================================================================
# 40-install-art.ps1
# Runs on WIN01 ONLY, after domain-join. Idempotent.
#
# Installs Invoke-AtomicRedTeam and the atomics library to C:\AtomicRedTeam.
# The Defender exclusion was already added in 10-common.ps1.
#
# Reference: https://github.com/redcanaryco/invoke-atomicredteam
# =============================================================================

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\bootstrap-state'
$LogPath  = 'C:\bootstrap-art.log'
Start-Transcript -Path $LogPath -Append -Force | Out-Null
Write-Host "=== 40-install-art.ps1 starting at $(Get-Date -Format o) ==="

$marker = Join-Path $StateDir '40-art.done'
if (Test-Path $marker) {
    Write-Host "ART already installed (skipping)"
    Stop-Transcript
    exit 0
}

# Ensure exclusion is in place (re-add idempotently, in case Defender state was reset)
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction SilentlyContinue

# Set process-scope execution policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# TLS 1.2 - required for github.com on Server 2022 default config
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install Invoke-AtomicRedTeam (the runner) + atomics (the test library)
Write-Host "Pulling Invoke-AtomicRedTeam installer"
$installerUrl = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
$installerPath = 'C:\AtomicRedTeam\install-atomicredteam.ps1'
New-Item -ItemType Directory -Path 'C:\AtomicRedTeam' -Force | Out-Null
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

Write-Host "Running ART installer (this also pulls the atomics library)"
& $installerPath -Force
Install-AtomicRedTeam -getAtomics -Force

# Verify
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
$count = (Invoke-AtomicTest All -ShowDetailsBrief 2>$null | Measure-Object).Count
Write-Host "ART installed. Atomics available: $count"

if ($count -lt 100) {
    Write-Warning "ART atomic count unexpectedly low ($count). Check logs."
}

New-Item -ItemType File -Path $marker -Force | Out-Null
Write-Host "=== 40-install-art.ps1 done at $(Get-Date -Format o) ==="
Stop-Transcript
