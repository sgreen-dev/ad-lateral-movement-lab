# Detection Coverage Matrix

> **Status:** skeleton — populated in Phase 4 alongside rule authoring.

Maps every authored detection to its MITRE ATT&CK technique, log source, false-positive profile, and validation status. This document is the auditable answer to *"what does your lab actually detect, and how do you know?"*

---

## Coverage table

| ATT&CK ID | Technique | Sigma rule | Log source(s) | Key fields | False-positive risk | Tested |
|---|---|---|---|---|---|---|
| T1021.002 | NTLM network logon | `T1021_002_smb_lateral_movement.yml` | Security 4624 | LogonType=3, AuthenticationPackageName=NTLM, TargetUserName | Medium — NTLM fallback / scanners | ⏳ |
| T1021.002 | SMB / Admin shares (variant) | `T1021.002_admin_share_access_anomalous.yml` | Security 5140/5145, Sysmon EID 3 | ShareName, RelativeTargetName | High — backup software | ⏳ |
| T1021.001 | RDP | `T1021.001_rdp_logon_unusual_source.yml` | Security 4624 | LogonType=10, IpAddress | Medium — admins legitimately RDP | ⏳ |
| T1021.006 | WinRM | `T1021.006_winrm_execution.yml` | Security 4624, Sysmon EID 1 | LogonType=3, ParentImage=wsmprovhost.exe | Low — narrow signal | ⏳ |
| T1059.001 | PowerShell | `T1059.001_powershell_post_winrm.yml` | Sysmon EID 1, PS 4104 | CommandLine, ScriptBlockText | Medium — legit admin scripts | ⏳ |
| Correlation | WinRM → PowerShell | _planned (Phase 4)_ | All above | Time-window join | Low | ⏳ |

---

## D3FEND coverage claimed

| D3FEND technique | How this lab covers it |
|---|---|
| D3-RAPA Remote Access Privilege Auditing | RDP/WinRM auth events monitored; alerts on anomalous source |
| D3-UA User Account Authentication | 4624/4648 correlation across hosts |
| D3-PA Process Analysis | Sysmon EID 1 parent-child tracking |

---

## ATT&CK Navigator layer

Layer JSON (`attack-navigator-layer.json`) is generated in Phase 4.
Once generated, view at: <https://mitre-attack.github.io/attack-navigator/> → Open Existing Layer → Upload from local.

---

## Validation status legend

| Symbol | Meaning |
|---|---|
| ✅ | True positive observed in lab; false positives reviewed and documented |
| ⏳ | Authored, not yet validated against live attack |
| ❌ | Authored, failed validation, needs tuning |
| 🔇 | Tuned out of production due to FP rate |
