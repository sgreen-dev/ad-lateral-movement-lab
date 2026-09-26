# Runbook: Lateral Movement Triage

> **Audience:** Tier 1/2 SOC analyst on shift.
> **Trigger:** Any alert from the native Wazuh rule pack [`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml) (group `ad_lateral_movement`), rule IDs `100210`–`100260` — see the table below. Each rule is a port of a Sigma rule in [`detections/sigma/`](../detections/sigma/).
> **Status:** v1.0 — pivots written against the lab's Wazuh field names ([operator guide §4 field cheat-sheet](operator-guide.md#field-cheat-sheet-windows-eventchannel--wazuh-field-names)). Not yet exercised against a live alert; verify field names against a real event before relying on them (operator guide §7b).

| Wazuh rule | Level | Technique | Sigma source |
|---|---|---|---|
| `100210` | 12 | T1021.006 WinRM — process spawned by `wsmprovhost.exe` | `T1021.006_winrm_execution.yml` |
| `100220` | 10 | T1021.002 NTLM network logon (4624 Type 3) | `T1021_002_smb_lateral_movement.yml` |
| `100230` | 10 | T1021.002 admin-share access (5145 `C$` / `ADMIN$`) | `T1021.002_admin_share_access_anomalous.yml` |
| `100240` | 10 | T1021.001 RDP logon (4624 Type 10) | `T1021.001_rdp_logon_unusual_source.yml` |
| `100250` | 12 | T1059.001 suspicious PowerShell script block (4104) | `T1059.001_powershell_post_winrm.yml` |
| `100260` | 14 | T1021.006 → T1059.001 chain on one host within 5 min | `correlation_winrm_to_powershell.yml` |

---

## 1. Initial triage (target: 5 minutes)

1. Confirm the alert in the Wazuh dashboard (Discover → `wazuh-alerts-*`, query `rule.id: "<rule ID>"`). Record these values from the alert — the pivots in §2 use them:
   - `rule.id`, `rule.description`, `rule.level`, `rule.mitre.id`
   - `<DEST_HOST>` = `agent.name` (e.g. `WIN01`) · `<SRC_IP>` = `data.win.eventdata.ipAddress` (logon/share rules) · `<USER>` = `data.win.eventdata.targetUserName`
   - `<T0>` = alert `timestamp` (UTC)
2. Check whether `<SRC_IP>` is a known jump host or admin workstation. The allow-list is to live in `docs/known-admin-hosts.md` (to be created); until then, treat only DC01 (`10.0.2.10`) as a known management source.
3. Check whether `<USER>` has any other authentication anomalies in the last 24 h: `data.win.system.eventID: ("4624" or "4625") and data.win.eventdata.targetUserName: "<USER>"`.

**Decision:**
- If source is allow-listed AND account behavior is normal → close as benign, document.
- Otherwise → escalate to investigation.

---

## 2. Investigation (target: 30 minutes)

For each alerted technique, follow the relevant pivot guide below. Queries are Wazuh DQL in Discover against `wazuh-archives-*` (raw events — see operator guide §4 for enabling the archives index); set the time picker to `<T0>` ± 1 h unless the row says otherwise. The equivalent SIEM-portable detection logic is in [`detections/splunk/`](../detections/splunk/) (SPL) and [`detections/kql/`](../detections/kql/) (KQL).

Sysmon events are selected with `data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"`, abbreviated below as `SYSMON and …`.

### T1021.001 RDP (`100240`)

| Pivot | Wazuh DQL | What you're looking for |
|---|---|---|
| All 4624 from source IP, last 24h | `data.win.system.eventID: "4624" and data.win.eventdata.ipAddress: "<SRC_IP>"` | Account spraying, reused source |
| Sysmon EID 1 on destination, post-logon window | `agent.name: "<DEST_HOST>" and SYSMON and data.win.system.eventID: "1"` | What did they execute after landing? |
| Sysmon EID 11 on destination, post-logon | `agent.name: "<DEST_HOST>" and SYSMON and data.win.system.eventID: "11"` (inspect `data.win.eventdata.targetFilename`) | Files dropped |
| Sysmon EID 3, post-logon | `agent.name: "<DEST_HOST>" and SYSMON and data.win.system.eventID: "3"` (inspect `data.win.eventdata.destinationIp`) | Outbound C2? |

SPL/KQL: `detections/splunk/T1021.001_rdp_logon_unusual_source.conf`, `detections/kql/T1021.001_rdp_logon_unusual_source.kql`.

### T1021.002 SMB (`100220`, `100230`)

| Pivot | Wazuh DQL | Looking for |
|---|---|---|
| 5145 on destination, last 24h | `agent.name: "<DEST_HOST>" and data.win.system.eventID: "5145"` (inspect `shareName`, `relativeTargetName`, `ipAddress`) | What shares/files were accessed |
| NTLM network logons from source | `data.win.system.eventID: "4624" and data.win.eventdata.logonType: "3" and data.win.eventdata.authenticationPackageName: "NTLM" and data.win.eventdata.ipAddress: "<SRC_IP>"` | Pass-the-hash / NTLM fallback pattern |
| Sysmon EID 1 on destination, parent=services.exe | `agent.name: "<DEST_HOST>" and SYSMON and data.win.system.eventID: "1" and data.win.eventdata.parentImage: *services.exe` | Remote service creation (PsExec-like) |

SPL/KQL: `T1021_002_smb_lateral_movement` and `T1021.002_admin_share_access_anomalous` in `detections/splunk/` and `detections/kql/`.

### T1021.006 WinRM (`100210`)

| Pivot | Wazuh DQL | Looking for |
|---|---|---|
| Sysmon EID 1, ParentImage=wsmprovhost.exe | `agent.name: "<DEST_HOST>" and SYSMON and data.win.system.eventID: "1" and data.win.eventdata.parentImage: *wsmprovhost.exe` | Commands executed under the WinRM session |
| PS 4104 on destination, post-logon | `agent.name: "<DEST_HOST>" and data.win.system.channel: "Microsoft-Windows-PowerShell/Operational" and data.win.system.eventID: "4104"` | Decoded script blocks |
| 4624 LogonType 3 to destination from same source | `agent.name: "<DEST_HOST>" and data.win.system.eventID: "4624" and data.win.eventdata.logonType: "3"` | Linked auth events (source host and account) |

SPL/KQL: `detections/splunk/T1021.006_winrm_execution.conf`, `detections/kql/T1021.006_winrm_execution.kql`. If `100260` also fired, work this section and the next together — the correlation means both halves landed on `<DEST_HOST>` within 5 minutes.

### T1059.001 PowerShell (`100250`, `100260`)

| Pivot | Wazuh DQL | Looking for |
|---|---|---|
| PS 4104 ScriptBlockText for known offensive patterns | `data.win.system.eventID: "4104" and data.win.eventdata.scriptBlockText: (*DownloadString* or *FromBase64String* or *amsiInitFailed* or *Invoke-Mimikatz* or *IEX*)` | Mimikatz, IEX, DownloadString, FromBase64 |
| Sysmon EID 1 powershell.exe with EncodedCommand flag | `SYSMON and data.win.system.eventID: "1" and data.win.eventdata.image: *powershell.exe and data.win.eventdata.commandLine: (*-enc* or *-EncodedCommand*)` | Decode the b64 — what does it do? |

SPL: `detections/splunk/T1059.001_powershell_post_winrm.conf`, `detections/splunk/correlation_winrm_to_powershell.conf`. KQL: `detections/kql/T1059.001_powershell_post_winrm.kql` (no KQL for the correlation — Kusto has no Sigma correlation support).

---

## 3. Containment

Before taking action, **document the live state** — running processes (`Get-Process`, `Get-CimInstance Win32_Process`), network connections (`Get-NetTCPConnection`), current sessions (`quser`) — so post-incident analysis isn't blocked by your own response. In the lab, run these through SSM (`terraform output -raw member_ssm_command` / `dc_ssm_command`).

| Severity | Action | Command (lab) | Authorization |
|---|---|---|---|
| High | Disable account in AD | On DC01: `Disable-ADAccount -Identity <USER>` | Self / SOC lead |
| High | Isolate host via SG modification | Swap the host onto a security group that denies all inbound/outbound except SSM: `aws ec2 modify-instance-attribute --instance-id <instance ID> --groups <isolation SG ID>` | Self / SOC lead |
| High | Reset credentials of every account that authenticated to the host in the last 24 h | On DC01: `Set-ADAccountPassword -Identity <account> -Reset` | IAM / SOC lead |
| Critical | Notify on-call IR + leadership | — | SOC lead |

Eradication/recovery in the lab is re-imaging, not cleaning: `terraform apply -replace=module.windows.aws_instance.member` (WIN01), then confirm the Wazuh agent re-enrolled (operator guide §2c). Worked example: [`docs/incident-report.md`](incident-report.md) §7.

---

## 4. Escalation criteria

Escalate to Tier 3 / IR if any of:
- Lateral movement reaches a domain controller
- Credential access events (T1003) observed
- Persistence mechanisms observed (T1547, T1053, T1078)
- More than 3 hosts involved
- C2 traffic to external IP confirmed
