# Atomic Red Team Test Plan

> **Status:** Complete — **lab exemplar.** The results below reflect the detection logic
> **validated in CI** ([`detections/wazuh/test_wazuh_rules.py`](../detections/wazuh/test_wazuh_rules.py) against [`local_rules.xml`](../detections/wazuh/local_rules.xml))
> and reconstructed end-to-end in [`docs/incident-report.md`](../docs/incident-report.md).
> Timestamps are **illustrative** and no rule has yet been observed firing in a live Wazuh run. To capture a live run, execute the sequence in the lab
> (see [`docs/operator-guide.md`](../docs/operator-guide.md)) and record the real UTC start times
> and observed events in the `Actual UTC start` / `Result` cells.

## Pre-flight

- [ ] All four lab hosts up (`terraform apply` clean)
- [ ] Wazuh dashboard reachable (`https://localhost:8443` via SSM port-forward)
- [ ] Both Windows agents reporting (Wazuh → Agents view)
- [ ] Sysmon channel ingesting (search for `EventID:1` in last 5 min)
- [ ] PS ScriptBlock logging confirmed (run `Write-Host "test"` on WIN01, see EID 4104)
- [ ] Atomic Red Team installed (`Invoke-AtomicTest -ListAll | Measure-Object` returns >0)
- [ ] Capture target `attack-emulation/raw-events.<date>.json` decided (gitignored)
- [ ] Kali private IP noted (`terraform output` — it is DHCP-assigned; `10.0.1.10` below is illustrative)
- [ ] Wall clock noted (UTC) — also note Wazuh server time, confirm clock skew < 5s

## Test sequence

> Run tests in order. After each, **wait 60 seconds** before the next so events
> serialize cleanly in the SIEM. Capture timestamp, command, expected events,
> and observed events for each.

### T1021.001-1 — RDP from Kali to WIN01

| Field | Value |
|---|---|
| Source | Kali (10.0.1.x, DHCP — `10.0.1.10` in examples) |
| Target | WIN01 (10.0.2.20) |
| Command | `xfreerdp /u:bob /p:'<bob_password>' /v:10.0.2.20 /cert-ignore +clipboard /size:1024x768` |
| Expected events on WIN01 | Security 4624 LogonType=10, Sysmon EID 1 (mstsc.exe context), Sysmon EID 3 |
| Expected alert | `T1021.001_rdp_logon_unusual_source.yml` → Wazuh rule `100240` |
| Actual UTC start | _illustrative_ |
| Result | ✅ `100240` fires (fixture-validated; live capture pending) |

### T1021.002-1 — Admin share access from WIN01

> Run from WIN01 to simulate "compromised foothold pivots to another share"

| Field | Value |
|---|---|
| Source | WIN01 (logged in as bob via earlier RDP session) |
| Target | DC01 (10.0.2.10) |
| Command | `net use \\DC01\C$ /user:lab\bob '<bob_password>'` then `copy notes.txt \\DC01\C$\Users\Public\` |
| Expected events on DC01 | Security 5140, 5145; Sysmon EID 3 from WIN01 source |
| Expected alert | `T1021.002_admin_share_access_anomalous.yml` → Wazuh rule `100230` |
| Actual UTC start | _illustrative_ |
| Result | ✅ `100230` fires (fixture-validated; live capture pending) |

> **Note:** addressing the share by hostname (`\DC01`) authenticates with Kerberos, so
> this test does **not** exercise the NTLM rule `100220`. That is covered by T1021.002-2.

### T1021.002-2 — NTLM network logon from Kali (by IP)

> Not yet run live. Targeting by **IP address** forces NTLM (no Kerberos SPN for an IP),
> which is what rule `100220` keys on.

| Field | Value |
|---|---|
| Source | Kali (10.0.1.x, DHCP) |
| Target | WIN01 (10.0.2.20) |
| Command | `nxc smb 10.0.2.20 -u bob -p '<bob_password>' -d lab.local --shares` (or `impacket-psexec 'lab.local/bob:<bob_password>@10.0.2.20'`) |
| Expected events on WIN01 | Security 4624 LogonType=3, `AuthenticationPackageName=NTLM`, `TargetUserName=bob` |
| Expected alert | `T1021_002_smb_lateral_movement.yml` → Wazuh rule `100220` |
| Actual UTC start | _not yet run_ |
| Result | ⏳ fixture-validated in CI; live capture pending |

### T1021.006-1 — WinRM execution from DC01 to WIN01

| Field | Value |
|---|---|
| Source | DC01 (as svc_backup) |
| Target | WIN01 |
| Command | `Invoke-Command -ComputerName WIN01 -Credential lab\svc_backup -ScriptBlock { whoami; hostname; Get-Process }` |
| Expected events on WIN01 | Security 4624 LogonType=3, Sysmon EID 1 with ParentImage=wsmprovhost.exe |
| Expected alert | `T1021.006_winrm_execution.yml` → Wazuh rule `100210` |
| Actual UTC start | 2026-08-20T14:02:13Z _(illustrative — see incident report §2)_ |
| Result | ✅ `100210` fires (fixture-validated; live capture pending) → exemplar walked in [incident report](../docs/incident-report.md) |

### T1059.001 — PowerShell payload via the WinRM session above

| Field | Value |
|---|---|
| Source | DC01 (continuing the WinRM session) |
| Target | WIN01 |
| Command | `Invoke-Command -ComputerName WIN01 -Credential lab\svc_backup -ScriptBlock { powershell -EncodedCommand <base64 of harmless 'whoami /priv'> }` |
| Expected events | Sysmon EID 1 with `-EncodedCommand`; PS 4104 with the decoded ScriptBlock |
| Expected alerts | `T1059.001_powershell_post_winrm.yml` (Wazuh `100250`) AND `correlation_winrm_to_powershell.yml` (Wazuh `100260`) |
| Actual UTC start | 2026-08-20T14:02:15Z _(illustrative — see incident report §2)_ |
| Result | ✅ `100250` + correlation `100260` fire (fixture-validated; live capture pending) → exemplar in [incident report](../docs/incident-report.md) |

## Post-execution

- [ ] Export full event set for the test window (Wazuh → discover → export JSON)
- [ ] Save to `attack-emulation/raw-events.<date>.json` (gitignored — sanitize before committing extracts)
- [ ] Sanitize and copy salient excerpts into `docs/incident-report.md`
- [ ] Verify all expected alerts fired; document any that didn't
