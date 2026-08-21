# Detection Coverage Matrix

> **Status:** Phases 3–4 complete. Five base rules plus a WinRM→PowerShell
> correlation rule, all with real UUIDs and `status: test`; SPL/KQL generated
> from source (correlation is SPL-only — Kusto has no correlation support); and
> an ATT&CK Navigator layer generated from rule tags. Every rule was confirmed
> firing as a true positive in Wazuh during the Phase 3 Atomic Red Team run
> (**Tested** = ✅). Each Sigma rule is also **ported to a native Wazuh rule**
> ([`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml), IDs
> `100210`–`100260`) — the form that actually runs in the deployed SIEM — with a
> true-positive/true-negative fixture per rule enforced in CI.

Maps every authored detection to its MITRE ATT&CK technique, log source, false-positive profile, and validation status. This document is the auditable answer to *"what does your lab actually detect, and how do you know?"*

---

## Coverage table

| ATT&CK ID | Technique | Sigma rule | Wazuh rule | Log source(s) | Key fields | False-positive risk | Tested |
|---|---|---|---|---|---|---|---|
| T1021.002 | NTLM network logon | `T1021_002_smb_lateral_movement.yml` | [`100220`](../detections/wazuh/local_rules.xml) | Security 4624 | LogonType=3, AuthenticationPackageName=NTLM, TargetUserName | Medium — NTLM fallback / scanners | ✅ |
| T1021.002 | SMB / Admin shares (variant) | `T1021.002_admin_share_access_anomalous.yml` | [`100230`](../detections/wazuh/local_rules.xml) | Security 5140/5145, Sysmon EID 3 | ShareName, RelativeTargetName | High — backup software | ✅ |
| T1021.001 | RDP | `T1021.001_rdp_logon_unusual_source.yml` | [`100240`](../detections/wazuh/local_rules.xml) | Security 4624 | LogonType=10, IpAddress | Medium — admins legitimately RDP | ✅ |
| T1021.006 | WinRM | `T1021.006_winrm_execution.yml` | [`100210`](../detections/wazuh/local_rules.xml) | Security 4624, Sysmon EID 1 | LogonType=3, ParentImage=wsmprovhost.exe | Low — narrow signal | ✅ |
| T1059.001 | PowerShell | `T1059.001_powershell_post_winrm.yml` | [`100250`](../detections/wazuh/local_rules.xml) | Sysmon EID 1, PS 4104 | CommandLine, ScriptBlockText | Medium — legit admin scripts | ✅ |
| T1021.006 → T1059.001 | WinRM → PowerShell (correlation) | `correlation_winrm_to_powershell.yml` | [`100260`](../detections/wazuh/local_rules.xml) | Sysmon EID 1 + PS 4104 | temporal join, group-by Computer, 5m | Low | ✅ |

> **Wazuh rule column** links to the native port in [`detections/wazuh/`](../detections/wazuh/).
> The **Tested ✅** here means a true positive was observed live during the Phase 3 run; the
> rule *logic* is additionally proven on every commit by a true-positive/true-negative fixture
> per rule (`python detections/wazuh/test_wazuh_rules.py`, gated in CI). See
> [`detections/wazuh/README.md`](../detections/wazuh/README.md) for the two-layer evidence model.

---

## D3FEND coverage claimed

| D3FEND technique | How this lab covers it |
|---|---|
| D3-RAPA Remote Access Privilege Auditing | RDP/WinRM auth events monitored; alerts on anomalous source |
| D3-UA User Account Authentication | 4624/4648 correlation across hosts |
| D3-PA Process Analysis | Sysmon EID 1 parent-child tracking |

---

## ATT&CK Navigator layer

Layer JSON: [`attack-navigator-layer.json`](attack-navigator-layer.json), generated
from the rules' `attack.*` tags by `scripts/generate_attack_layer.py` (CI verifies
it stays in sync). Covers T1021.001/.002/.006, T1059.001, T1027.010, T1550.002.
View at: <https://mitre-attack.github.io/attack-navigator/> → Open Existing Layer → Upload from local.

---

## Validation status legend

| Symbol | Meaning |
|---|---|
| ✅ | True positive observed in lab; false positives reviewed and documented |
| ⏳ | Authored, not yet validated against live attack |
| ❌ | Authored, failed validation, needs tuning |
| 🔇 | Tuned out of production due to FP rate |
