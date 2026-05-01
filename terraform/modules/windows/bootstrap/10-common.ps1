# =============================================================================
# 10-common.ps1
# Runs on BOTH hosts (DC and member). Idempotent.
#
# Steps:
#   1. Add Defender exclusion for C:\AtomicRedTeam (so ART doesn't get nuked)
#   2. Install Sysmon with SwiftOnSecurity config
#   3. Enable advanced audit policy for lateral-movement detection
#   4. Enable PowerShell ScriptBlock + Module logging
#   5. Install Wazuh agent (if WAZUH_IP env var is set)
# =============================================================================

$ErrorActionPreference = 'Stop'
$StateDir = 'C:\bootstrap-state'
$LogPath  = 'C:\bootstrap-common.log'
Start-Transcript -Path $LogPath -Append -Force | Out-Null
Write-Host "=== 10-common.ps1 starting at $(Get-Date -Format o) ==="

# -----------------------------------------------------------------------------
# 1. Defender exclusion for ART
# -----------------------------------------------------------------------------
$marker = Join-Path $StateDir '10-defender-exclusion.done'
if (-not (Test-Path $marker)) {
    Write-Host "[1/5] Adding Defender exclusion for C:\AtomicRedTeam"
    New-Item -ItemType Directory -Path 'C:\AtomicRedTeam' -Force | Out-Null
    Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction SilentlyContinue
    # Sanity check
    $exclusions = (Get-MpPreference).ExclusionPath
    Write-Host "Defender exclusions now: $($exclusions -join ', ')"
    New-Item -ItemType File -Path $marker -Force | Out-Null
} else {
    Write-Host "[1/5] Defender exclusion already configured (skipping)"
}

# -----------------------------------------------------------------------------
# 2. Sysmon with SwiftOnSecurity config
# -----------------------------------------------------------------------------
$marker = Join-Path $StateDir '10-sysmon.done'
if (-not (Test-Path $marker)) {
    Write-Host "[2/5] Installing Sysmon"
    $tmp = 'C:\sysmon-install'
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null

    # Sysinternals Sysmon
    $sysmonZip = Join-Path $tmp 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $sysmonZip -UseBasicParsing
    Expand-Archive -Path $sysmonZip -DestinationPath $tmp -Force

    # SwiftOnSecurity config — pinned to a specific commit for reproducibility
    # Reference: https://github.com/SwiftOnSecurity/sysmon-config
    $configUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
    $configPath = Join-Path $tmp 'sysmonconfig.xml'
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing

    # Install (works on AMD64 — for ARM hosts use Sysmon.exe; we're x86_64)
    & "$tmp\Sysmon64.exe" -accepteula -i $configPath
    Start-Sleep -Seconds 3

    # Verify channel exists
    $channel = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
    if ($null -eq $channel) {
        throw "Sysmon channel did not appear after install"
    }

    # Bump channel size to 1 GB so we don't lose events during attack runs
    wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
    Write-Host "Sysmon installed. Channel size set to 1 GB."

    New-Item -ItemType File -Path $marker -Force | Out-Null
} else {
    Write-Host "[2/5] Sysmon already installed (skipping)"
}

# -----------------------------------------------------------------------------
# 3. Advanced audit policy
# -----------------------------------------------------------------------------
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
$marker = Join-Path $StateDir '10-auditpol.done'
if (-not (Test-Path $marker)) {
    Write-Host "[3/5] Enabling advanced audit policy"

    $subcategories = @(
        # Logon/Logoff
        @{ Name = 'Logon';                          S = $true;  F = $true  },
        @{ Name = 'Logoff';                         S = $true;  F = $false },
        @{ Name = 'Special Logon';                  S = $true;  F = $false },
        @{ Name = 'Account Lockout';                S = $true;  F = $true  },
        @{ Name = 'Other Logon/Logoff Events';      S = $true;  F = $true  },
        # Account Logon
        @{ Name = 'Credential Validation';          S = $true;  F = $true  },
        @{ Name = 'Kerberos Authentication Service'; S = $true; F = $true  },
        @{ Name = 'Kerberos Service Ticket Operations'; S = $true; F = $true },
        # Detailed Tracking
        @{ Name = 'Process Creation';               S = $true;  F = $false },
        @{ Name = 'Process Termination';            S = $true;  F = $false },
        # Object Access
        @{ Name = 'File Share';                     S = $true;  F = $true  },
        @{ Name = 'Detailed File Share';            S = $true;  F = $false }
    )

    foreach ($sub in $subcategories) {
        $args = @('/set', "/subcategory:$($sub.Name)")
        $args += if ($sub.S) { '/success:enable' } else { '/success:disable' }
        $args += if ($sub.F) { '/failure:enable' } else { '/failure:disable' }
        & auditpol.exe @args | Out-Null
    }

    # Enable command-line auditing in Process Creation events (4688)
    # Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
    $regKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
    Set-ItemProperty -Path $regKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

    Write-Host "Audit policy applied."
    New-Item -ItemType File -Path $marker -Force | Out-Null
} else {
    Write-Host "[3/5] Audit policy already configured (skipping)"
}

# -----------------------------------------------------------------------------
# 4. PowerShell ScriptBlock and Module logging
# -----------------------------------------------------------------------------
$marker = Join-Path $StateDir '10-pslogging.done'
if (-not (Test-Path $marker)) {
    Write-Host "[4/5] Enabling PowerShell ScriptBlock + Module logging"

    # ScriptBlock logging (4104)
    $sbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbKey)) { New-Item -Path $sbKey -Force | Out-Null }
    Set-ItemProperty -Path $sbKey -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord

    # Module logging (4103)
    $modKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modKey)) { New-Item -Path $modKey -Force | Out-Null }
    Set-ItemProperty -Path $modKey -Name 'EnableModuleLogging' -Value 1 -Type DWord

    $modNamesKey = "$modKey\ModuleNames"
    if (-not (Test-Path $modNamesKey)) { New-Item -Path $modNamesKey -Force | Out-Null }
    Set-ItemProperty -Path $modNamesKey -Name '*' -Value '*' -Type String

    Write-Host "PS logging enabled."
    New-Item -ItemType File -Path $marker -Force | Out-Null
} else {
    Write-Host "[4/5] PS logging already configured (skipping)"
}

# -----------------------------------------------------------------------------
# 5. Wazuh agent (if manager IP is known)
# -----------------------------------------------------------------------------
$marker = Join-Path $StateDir '10-wazuh.done'
if (-not (Test-Path $marker)) {
    if ([string]::IsNullOrWhiteSpace($env:LAB_WAZUH_IP)) {
        Write-Host "[5/5] Wazuh manager IP not set — skipping agent install. Re-run bootstrap or install manually after Wazuh is up."
    } else {
        Write-Host "[5/5] Installing Wazuh agent, manager = $env:LAB_WAZUH_IP"
        $tmp = 'C:\wazuh-install'
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $msi = Join-Path $tmp 'wazuh-agent.msi'
        # Wazuh 4.x Windows agent — pin a major version
        $url = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi'
        Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

        $hostname = $env:COMPUTERNAME
        $args = @(
            '/i', $msi,
            '/q',
            "WAZUH_MANAGER=$env:LAB_WAZUH_IP",
            "WAZUH_AGENT_NAME=$hostname",
            "WAZUH_REGISTRATION_SERVER=$env:LAB_WAZUH_IP"
        )
        Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -NoNewWindow

        # Configure agent to ship Sysmon channel
        $confPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
        if (Test-Path $confPath) {
            $localfileBlock = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
            $conf = Get-Content $confPath -Raw
            if ($conf -notmatch 'Microsoft-Windows-Sysmon/Operational') {
                $conf = $conf -replace '</ossec_config>', "$localfileBlock`n</ossec_config>"
                Set-Content -Path $confPath -Value $conf -Encoding UTF8
                Write-Host "Added Sysmon + PowerShell channels to Wazuh agent config."
            }
        }

        Start-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
        Set-Service -Name 'WazuhSvc' -StartupType Automatic -ErrorAction SilentlyContinue

        New-Item -ItemType File -Path $marker -Force | Out-Null
    }
} else {
    Write-Host "[5/5] Wazuh agent already installed (skipping)"
}

Write-Host "=== 10-common.ps1 done at $(Get-Date -Format o) ==="
Stop-Transcript
