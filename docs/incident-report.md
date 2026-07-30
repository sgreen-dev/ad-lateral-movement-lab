# Incident Report — Simulated Lateral Movement via WinRM and PowerShell

> **Status:** skeleton — populated in Phase 5 after attack execution. All values below are placeholders.
> **Framework alignment:** NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide). MITRE ATT&CK v15.
> **Classification:** Lab / Training. No real-world impact.

---

## 1. Executive Summary

*(3–5 sentences, written for a non-technical reader. Your GRC voice goes here. State: what happened, when it was detected, what was affected, what the response was, what the residual risk is.)*

> Example phrasing to adapt:
> *"On [DATE], a simulated lateral movement attack chain was detected on lab member server WIN01.lab.local. An attacker leveraged a previously-compromised service account (svc_backup) to authenticate via WinRM from an unauthorized source host and execute encoded PowerShell. Detection occurred within X minutes of initial compromise via Sigma rule [ID] correlating Windows Event 4624 with Sysmon Event ID 1. Containment was completed within Y minutes; no data was exfiltrated. Residual gaps: [list]."*

---

## 2. Incident Timeline (UTC)

| Time (UTC) | Source | Event | Notes |
|---|---|---|---|
| TBD | Wazuh | Initial alert: rule `winrm_execution.yml` fired | Severity: high |
| TBD | Manual | Analyst triage begin | |
| TBD | Wazuh | Correlated Sysmon EID 1 (powershell.exe under wsmprovhost) | |
| TBD | Manual | Pivot: identified source IP and account | |
| TBD | Manual | Containment: disabled svc_backup | |
| TBD | Manual | Eradication: WIN01 isolated via SG modification | |
| TBD | Manual | Post-incident: report drafted | |

---

## 3. Affected Assets

| Asset | Role | Compromise indicator |
|---|---|---|
| WIN01.lab.local | Member server (lateral movement target) | TBD |
| svc_backup@lab.local | Service account | TBD |
| DC01.lab.local | Domain controller (origin of WinRM session in this scenario) | TBD |

---

## 4. Indicators of Compromise

| Type | Value | Source event |
|---|---|---|
| Source IP | TBD | 4624 IpAddress field |
| Account | svc_backup | 4624 TargetUserName |
| Process | powershell.exe (PID TBD) | Sysmon EID 1 |
| Parent process | wsmprovhost.exe | Sysmon EID 1 ParentImage |
| Command line (decoded) | TBD | Sysmon EID 1 + 4104 ScriptBlockText |
| File hash (if dropped) | TBD | Sysmon EID 11 |
| Network connection | TBD:5985/5986 | Sysmon EID 3 |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence |
|---|---|---|---|
| TA0008 Lateral Movement | T1021 Remote Services | T1021.006 WinRM | EID 4624 LogonType 3 + wsmprovhost parent |
| TA0002 Execution | T1059 Command/Scripting Interpreter | T1059.001 PowerShell | Sysmon EID 1 + EID 4104 |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.010 Command Obfuscation | `-EncodedCommand` flag observed |

---

## 6. Detection Logic

### Primary alert
- **Sigma rule:** `detections/sigma/T1021.006_winrm_execution.yml`
- **SIEM:** Wazuh (rule ID: TBD after deployment)
- **Logic summary:** match Windows Security 4624 with LogonType=3 where target host is in scope, correlate with Sysmon EID 1 within 60s where ParentImage = `wsmprovhost.exe`.

### Correlation rule
- **Sigma rule:** `detections/sigma/correlation_winrm_to_powershell.yml`
- **Logic summary:** join WinRM auth event to subsequent PowerShell execution by user/host within a 5-minute window.

### Why it fired here
*(Walk through the actual fields from the alert. Show that you understand the detection, not just that it triggered.)*

---

## 7. Containment, Eradication, and Recovery

| Phase | Action | Owner | Justification |
|---|---|---|---|
| Containment (short-term) | Isolate WIN01 via SG modification (deny egress) | SOC | Stop active beaconing without forensic destruction |
| Containment (short-term) | Disable svc_backup AD account | SOC / IAM | Prevent re-use |
| Containment (long-term) | Force password reset for all accounts that authenticated to WIN01 in last 24h | IAM | Address potential credential theft from session |
| Eradication | Re-image WIN01 from known-good Terraform state | IR / Cloud | Faster than forensic clean for ephemeral lab host; document the trade-off |
| Recovery | Re-deploy WIN01 via `terraform apply -target=...` | IR / Cloud | |
| Recovery | Confirm no persistence remained on DC01 | IR | |

---

## 8. Lessons Learned & Detection Gaps

*(This is the highest-value section for a hiring manager — it shows you can reflect, not just react.)*

**What worked**
- TBD

**What didn't**
- TBD

**Detection gaps identified**
- TBD (e.g., no alert on initial credential theft on DC01; only caught at WinRM stage)

**Recommended improvements**
- TBD (e.g., add EID 4648 explicit-credential-use rule; tune Sysmon config for WMI activity)

---

## 9. NIST 800-61 Phase Mapping

| 800-61 Phase | This incident's activities |
|---|---|
| Preparation | Sysmon deployment, audit policy hardening, Wazuh ruleset, IR runbook (`docs/runbook-lateral-movement.md`) |
| Detection & Analysis | Wazuh alert → analyst triage → correlation across Security/Sysmon/PowerShell channels |
| Containment, Eradication, Recovery | Account disablement, host isolation, re-imaging |
| Post-Incident Activity | This report; detection rule tuning; runbook updates |

---

## 10. Appendix

- A. Raw event excerpts (sanitized) — `attack-emulation/raw-events.md`
- B. Sigma rule full text — `detections/sigma/`
- C. SIEM screenshots — `screenshots/`
- D. Atomic Red Team test plan executed — `attack-emulation/atomic-test-plan.md`
