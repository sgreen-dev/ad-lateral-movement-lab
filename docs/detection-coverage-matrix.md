# Detection Coverage Matrix

> **Status:** Phases 3–4 complete. Five base rules plus a WinRM→PowerShell
> correlation rule, all with real UUIDs (five `status: test`; the NTLM
> network-logon rule is still `status: experimental`); SPL/KQL generated from
> source (correlation is SPL-only — Kusto has no correlation support); and an
> ATT&CK Navigator layer generated from rule tags. Each Sigma rule is **ported to
> a native Wazuh rule** ([`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml),
> IDs `100210`–`100260`) — the form that actually runs in the deployed SIEM — with
> a true-positive/true-negative fixture per rule enforced in CI (**Tested** = ✅
> fixture-validated). No rule has yet been observed firing in a live lab run;
> live capture is pending.

Maps every authored detection to its MITRE ATT&CK technique, log source, false-positive profile, and validation status. This document is the auditable answer to *"what does your lab actually detect, and how do you know?"*

---

## Coverage table

| ATT&CK ID | Technique | Sigma rule | Wazuh rule | Log source(s) | Key fields | False-positive risk | Tested |
|---|---|---|---|---|---|---|---|
| T1021.002 | NTLM network logon | `T1021_002_smb_lateral_movement.yml` | [`100220`](../detections/wazuh/local_rules.xml) | Security 4624 | LogonType=3, AuthenticationPackageName=NTLM, TargetUserName | Medium — NTLM fallback / scanners | ✅ |
| T1021.002 | SMB / Admin shares (variant) | `T1021.002_admin_share_access_anomalous.yml` | [`100230`](../detections/wazuh/local_rules.xml) | Security 5145 | ShareName ends `\C$` / `\ADMIN$`, IpAddress ≠ DC01 (`10.0.2.10`) | High — backup software | ✅ |
| T1021.001 | RDP | `T1021.001_rdp_logon_unusual_source.yml` | [`100240`](../detections/wazuh/local_rules.xml) | Security 4624 | LogonType=10, IpAddress | Medium — admins legitimately RDP | ✅ |
| T1021.006 | WinRM | `T1021.006_winrm_execution.yml` | [`100210`](../detections/wazuh/local_rules.xml) | Sysmon EID 1 (process_creation) | ParentImage ends `\wsmprovhost.exe` | Low — narrow signal | ✅ |
| T1059.001 | PowerShell | `T1059.001_powershell_post_winrm.yml` | [`100250`](../detections/wazuh/local_rules.xml) | PowerShell 4104 (ps_script) | ScriptBlockText (encoded command / download cradle / AMSI bypass) | Medium — legit admin scripts | ✅ |
| T1021.006 → T1059.001 | WinRM → PowerShell (correlation) | `correlation_winrm_to_powershell.yml` | [`100260`](../detections/wazuh/local_rules.xml) | Sysmon EID 1 + PS 4104 | temporal join, group-by Computer, 5m | Low | ✅ |

> **Wazuh rule column** links to the native port in [`detections/wazuh/`](../detections/wazuh/).
> The **Tested ✅** here means **fixture-validated**: the rule *logic* is proven on every change
> to the rule pack by a true-positive/true-negative fixture per rule
> (`python detections/wazuh/test_wazuh_rules.py`, gated in CI). Live capture in a running lab is
> still pending. See
> [`detections/wazuh/README.md`](../detections/wazuh/README.md) for the two-layer evidence model.

---

## D3FEND coverage claimed

| D3FEND technique | How this lab covers it |
|---|---|
| D3-RAPA Remote Access Privilege Auditing | RDP/WinRM auth events monitored; alerts on anomalous source |
| D3-UA User Account Authentication | 4624 logon-type/auth-package analysis (Type 3 NTLM, Type 10) across hosts |
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
| ✅ | Fixture-validated in CI (fires on positive fixture, silent on negative); false positives reviewed and documented |
| ⏳ | Authored, not yet validated |
| ❌ | Authored, failed validation, needs tuning |
| 🔇 | Tuned out of production due to FP rate |
