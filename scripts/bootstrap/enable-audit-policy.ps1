# =============================================================================
# enable-audit-policy.ps1
# Enables the Windows audit subcategories needed for lateral movement detection.
# Idempotent.
# Populated in Phase 2.
# =============================================================================
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations

# TODO Phase 2 — turn on these subcategories (Success+Failure unless noted):
#
# Logon/Logoff:
#   - Logon                       (4624, 4625)
#   - Logoff                      (4634, 4647)
#   - Special Logon               (4672, 4964)
#   - Account Lockout             (4740)
#   - Other Logon/Logoff Events   (4648, 4649, 4778, 4779)
#
# Account Logon:
#   - Credential Validation       (4776)
#   - Kerberos Authentication Service (4768)
#   - Kerberos Service Ticket Operations (4769, 4770)
#
# Detailed Tracking:
#   - Process Creation            (4688) — and enable command-line in 4688 via reg key
#   - Process Termination         (4689)
#
# Object Access:
#   - File Share                  (5140, 5142, 5143, 5144, 5145)
#   - Detailed File Share         (5145 with detailed object access)
#
# Plus:
#   - Enable PowerShell Module Logging       (4103)
#   - Enable PowerShell ScriptBlock Logging  (4104)
#
# Use auditpol.exe /set /subcategory:"<Name>" /success:enable /failure:enable
# Then verify with: auditpol /get /category:*

Write-Host "Audit policy bootstrap stub — populated in Phase 2"
