# Atomic Red Team Test Plan

> **Status:** skeleton — populated in Phase 3 with real timestamps and command outputs.

## Pre-flight

- [ ] All four lab hosts up (`terraform apply` clean)
- [ ] Wazuh dashboard reachable (`https://localhost:8443` via SSM port-forward)
- [ ] Both Windows agents reporting (Wazuh → Agents view)
- [ ] Sysmon channel ingesting (search for `EventID:1` in last 5 min)
- [ ] PS ScriptBlock logging confirmed (run `Write-Host "test"` on WIN01, see EID 4104)
- [ ] Atomic Red Team installed (`Invoke-AtomicTest -ListAll | Measure-Object` returns >0)
- [ ] `attack-emulation/raw-events.md` created and ready for capture
- [ ] Wall clock noted (UTC) — also note Wazuh server time, confirm clock skew < 5s

## Test sequence

> Run tests in order. After each, **wait 60 seconds** before the next so events
> serialize cleanly in the SIEM. Capture timestamp, command, expected events,
> and observed events for each.

### T1021.001-1 — RDP from Kali to WIN01

| Field | Value |
|---|---|
| Source | Kali (10.0.1.10) |
| Target | WIN01 (10.0.2.20) |
| Command | `xfreerdp /u:bob /p:'<bob_password>' /v:10.0.2.20 /cert-ignore +clipboard /size:1024x768` |
| Expected events on WIN01 | Security 4624 LogonType=10, Sysmon EID 1 (mstsc.exe context), Sysmon EID 3 |
| Expected alert | `T1021.001_rdp_logon_unusual_source.yml` |
| Actual UTC start | TBD |
| Result | ⏳ |

### T1021.002-1 — Admin share access from WIN01

> Run from WIN01 to simulate "compromised foothold pivots to another share"

| Field | Value |
|---|---|
| Source | WIN01 (logged in as bob via earlier RDP session) |
| Target | DC01 (10.0.2.10) |
| Command | `net use \\DC01\C$ /user:lab\bob '<bob_password>'` then `copy notes.txt \\DC01\C$\Users\Public\` |
| Expected events on DC01 | Security 5140, 5145; Sysmon EID 3 from WIN01 source |
| Expected alert | `T1021.002_admin_share_access_anomalous.yml` |
| Actual UTC start | TBD |
| Result | ⏳ |

### T1021.006-1 — WinRM execution from DC01 to WIN01

| Field | Value |
|---|---|
| Source | DC01 (as svc_backup) |
| Target | WIN01 |
| Command | `Invoke-Command -ComputerName WIN01 -Credential lab\svc_backup -ScriptBlock { whoami; hostname; Get-Process }` |
| Expected events on WIN01 | Security 4624 LogonType=3, Sysmon EID 1 with ParentImage=wsmprovhost.exe |
| Expected alert | `T1021.006_winrm_execution.yml` |
| Actual UTC start | TBD |
| Result | ⏳ |

### T1059.001 — PowerShell payload via the WinRM session above

| Field | Value |
|---|---|
| Source | DC01 (continuing the WinRM session) |
| Target | WIN01 |
| Command | `Invoke-Command -ComputerName WIN01 -Credential lab\svc_backup -ScriptBlock { powershell -EncodedCommand <base64 of harmless 'whoami /priv'> }` |
| Expected events | Sysmon EID 1 with `-EncodedCommand`; PS 4104 with the decoded ScriptBlock |
| Expected alerts | `T1059.001_powershell_post_winrm.yml` AND `correlation_winrm_to_powershell.yml` |
| Actual UTC start | TBD |
| Result | ⏳ |

## Post-execution

- [ ] Export full event set for the test window (Wazuh → discover → export JSON)
- [ ] Save to `attack-emulation/raw-events.<date>.json` (gitignored — sanitize before committing extracts)
- [ ] Sanitize and copy salient excerpts into `docs/incident-report.md`
- [ ] Verify all expected alerts fired; document any that didn't
