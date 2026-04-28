# =============================================================================
# install-sysmon.ps1
# Installs Sysmon with the SwiftOnSecurity config.
# Idempotent — safe to re-run.
# Populated in Phase 2.
# =============================================================================
# Reference: https://github.com/SwiftOnSecurity/sysmon-config
# Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# TODO Phase 2:
# - Download Sysmon zip from sysinternals
# - Download SwiftOnSecurity sysmonconfig-export.xml (pin to a specific commit SHA)
# - Verify hashes
# - Install with: Sysmon64.exe -accepteula -i sysmonconfig.xml
# - Confirm event channel exists: Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational
# - Set channel max size to 1 GB

Write-Host "Sysmon bootstrap stub — populated in Phase 2"
