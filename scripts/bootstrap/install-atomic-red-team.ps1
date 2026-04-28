# =============================================================================
# install-atomic-red-team.ps1
# Installs the Atomic Red Team test harness on the host.
# WARNING: This script disables Windows Defender real-time scanning on the
#          install path because ART payloads will (correctly) be flagged.
#          ONLY run inside the lab environment.
# Populated in Phase 2/3.
# =============================================================================
# Reference: https://github.com/redcanaryco/atomic-red-team
# Reference: https://github.com/redcanaryco/invoke-atomicredteam

# TODO Phase 2/3:
# - Add Defender exclusion for C:\AtomicRedTeam
# - Set-ExecutionPolicy Bypass -Scope Process
# - Install Invoke-AtomicRedTeam:
#     IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
#     Install-AtomicRedTeam -getAtomics -Force
# - Verify with: Invoke-AtomicTest T1021.001 -ShowDetailsBrief

Write-Host "ART bootstrap stub — populated in Phase 2/3"
