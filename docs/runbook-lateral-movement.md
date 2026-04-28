# Runbook: Lateral Movement Triage

> **Audience:** Tier 1/2 SOC analyst on shift.
> **Trigger:** Any alert from rules in `detections/sigma/T1021.*` or `correlation_winrm_to_powershell.yml`.
> **Status:** skeleton — populated in Phase 5.

---

## 1. Initial triage (target: 5 minutes)

1. Confirm the alert in Wazuh dashboard. Note:
   - Rule name and Sigma ID
   - Source host, destination host, account, timestamp
   - Severity
2. Check whether source host is a known jump host or admin workstation. (Maintain this allow-list in `docs/known-admin-hosts.md` — TBD.)
3. Check whether the account has any other recent authentication anomalies in last 24h.

**Decision:**
- If source is allow-listed AND account behavior is normal → close as benign, document.
- Otherwise → escalate to investigation.

---

## 2. Investigation (target: 30 minutes)

For each alerted technique, follow the relevant pivot guide below.

### T1021.001 RDP

| Pivot | Wazuh / SPL query (TBD) | What you're looking for |
|---|---|---|
| All 4624 from source IP, last 24h | TBD | Account spraying, reused source |
| Sysmon EID 1 on destination, post-logon window | TBD | What did they execute after landing? |
| Sysmon EID 11 on destination, post-logon | TBD | Files dropped |
| Sysmon EID 3, post-logon | TBD | Outbound C2? |

### T1021.002 SMB

| Pivot | Query | Looking for |
|---|---|---|
| 5145 on destination, last 24h | TBD | What shares/files were accessed |
| Sysmon EID 1 on destination, parent=services.exe | TBD | Remote service creation (PsExec-like) |

### T1021.006 WinRM

| Pivot | Query | Looking for |
|---|---|---|
| Sysmon EID 1, ParentImage=wsmprovhost.exe | TBD | Commands executed under the WinRM session |
| PS 4104 on destination, post-logon | TBD | Decoded script blocks |
| 4624 LogonType 3 to destination from same source | TBD | Linked auth events |

### T1059.001 PowerShell

| Pivot | Query | Looking for |
|---|---|---|
| PS 4104 ScriptBlockText for known offensive patterns | TBD | Mimikatz, IEX, DownloadString, FromBase64 |
| Sysmon EID 1 powershell.exe with EncodedCommand flag | TBD | Decode the b64 — what does it do? |

---

## 3. Containment

Before taking action, **document the live state** — running processes, network connections, current sessions — so post-incident analysis isn't blocked by your own response.

| Severity | Action | Authorization |
|---|---|---|
| High | Disable account in AD | Self / SOC lead |
| High | Isolate host via SG modification | Self / SOC lead |
| Critical | Notify on-call IR + leadership | SOC lead |

Containment commands and runbooks: TBD (Phase 5).

---

## 4. Escalation criteria

Escalate to Tier 3 / IR if any of:
- Lateral movement reaches a domain controller
- Credential access events (T1003) observed
- Persistence mechanisms observed (T1547, T1053, T1078)
- More than 3 hosts involved
- C2 traffic to external IP confirmed
