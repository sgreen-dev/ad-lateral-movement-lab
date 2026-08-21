# Native Wazuh Detections

The lab's authoritative detections are **Sigma** ([`../sigma/`](../sigma/)); this directory is
the **native Wazuh port** — the rules that actually run in the SIEM this lab deploys. Wazuh has
no official Sigma backend, so the port is manual, one Wazuh rule per Sigma rule, same
selection/filter logic. This closes the loop: *"the detections I wrote run in the SIEM I stood
up, and here's the evidence they fire on the right events and stay quiet on the wrong ones."*

## Contents

| File | What it is |
|---|---|
| [`local_rules.xml`](local_rules.xml) | The 6 rules (5 base + 1 correlation), IDs `100210`–`100260` |
| [`ossec.conf.snippet`](ossec.conf.snippet) | Agent channel forwarding + optional manager archiving |
| [`evidence/`](evidence/) | Positive + negative fixture per base rule (Wazuh decoded-alert shape) |
| [`test_wazuh_rules.py`](test_wazuh_rules.py) | Offline validator: proves TP/TN per rule + correlation wiring |

## Rule map

| Wazuh rule | Lvl | ATT&CK | Fires on | Sigma source | Atomic that triggers it |
|---|---|---|---|---|---|
| `100210` | 12 | T1021.006 | child process of `wsmprovhost.exe` (Sysmon EID 1) | [`T1021.006_winrm_execution.yml`](../sigma/T1021.006_winrm_execution.yml) | WinRM `Invoke-Command` from DC01 (`T1021.006-1`) |
| `100220` | 10 | T1021.002 / T1550.002 | NTLM 4624 / Type 3 by a user account | [`T1021_002_smb_lateral_movement.yml`](../sigma/T1021_002_smb_lateral_movement.yml) | NTLM network logon from Kali (NetExec / psexec) |
| `100230` | 10 | T1021.002 | 5145 access to `C$` / `ADMIN$` from a non-DC source | [`T1021.002_admin_share_access_anomalous.yml`](../sigma/T1021.002_admin_share_access_anomalous.yml) | `net use \\DC01\C$` + copy (`T1021.002-1`) |
| `100240` | 10 | T1021.001 | RDP 4624 / Type 10 from a non-local source | [`T1021.001_rdp_logon_unusual_source.yml`](../sigma/T1021.001_rdp_logon_unusual_source.yml) | `xfreerdp` from Kali (`T1021.001-1`) |
| `100250` | 12 | T1059.001 / T1027.010 | PowerShell 4104 with encoded / cradle / AMSI indicators | [`T1059.001_powershell_post_winrm.yml`](../sigma/T1059.001_powershell_post_winrm.yml) | encoded PS via the WinRM session (`T1059.001`) |
| `100260` | 14 | T1021.006 → T1059.001 | `100210` **then** `100250` on the same host ≤ 5 min | [`correlation_winrm_to_powershell.yml`](../sigma/correlation_winrm_to_powershell.yml) | run the WinRM then the PowerShell atomic |

Atomic references map to [`../../attack-emulation/atomic-test-plan.md`](../../attack-emulation/atomic-test-plan.md).

## Install (on the Wazuh manager)

```bash
# 1. Drop the rules in (custom rules auto-load from this path)
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml

# 2. Reload
sudo systemctl restart wazuh-manager

# 3. Confirm they loaded (no XML errors, rules listed)
sudo /var/ossec/bin/wazuh-logtest -v 2>&1 | head    # 'Session initialized' = ruleset compiled OK
```

Agents must be forwarding the Sysmon and PowerShell channels for `100210` / `100250` to have
input — the Windows bootstrap already configures this; see [`ossec.conf.snippet`](ossec.conf.snippet).

## Evidence: what "tested" means here

Two layers, kept honest and separate:

**1. Rule-logic validation (in-repo, automated, runs anywhere).**
[`test_wazuh_rules.py`](test_wazuh_rules.py) evaluates each rule's field conditions against a
**positive** fixture (must fire) and a **negative** look-alike (must stay silent) — a true
positive and a true negative per rule — plus a structural check that the correlation rule chains
`100210 → 100250` on the same host. No Wazuh install needed:

```bash
python detections/wazuh/test_wazuh_rules.py
#   [PASS] T1021.006_winrm_execution.positive.json  rule 100210 expect=True  got=True
#   [PASS] T1021.006_winrm_execution.negative.json  rule 100210 expect=False got=False
#   ... 10/10 fixtures behaved as expected
```

This validates the **discriminating logic** (Wazuh PCRE2 `<field>` semantics: unanchored search,
`(?i)` for case, `negate="yes"` to invert). It does **not** re-implement the Wazuh engine —
decoder output, `<if_group>` / `<decoded_as>` preconditions, and the temporal
`<if_matched_sid>` correlation are validated live, below.

**2. Live true-positive capture (run in the lab).**
The definitive proof is the rule firing on a real event. After installing the rules:

```
1. Run the atomic from the rule map (operator-guide §5).
2. In Discover, query   rule.id: "100210"   (or rule.mitre.id: "T1021.006")
   over your test window -> the alert is your receipt.
3. Save it: Share -> CSV/JSON, into attack-emulation/raw-events.<date>.json (sanitize).
```

### Validate the correlation rule (100260)

A fixture can't exercise timing, so validate `100260` live: run the **WinRM** atomic
(`T1021.006`) and then, within 5 minutes and on the **same host**, the **PowerShell** atomic
(`T1059.001`). Then query `rule.id: "100260"` — it fires only when both base rules matched on
one host inside the window, which is the WinRM→PowerShell kill chain the incident report walks.

## Field names

The rules use the `windows_eventchannel` decoder field convention: `win.system.*` (envelope)
and `win.eventdata.*` (payload, first letter lower-cased — e.g. `win.eventdata.parentImage`,
`win.eventdata.ipAddress`, `win.eventdata.scriptBlockText`). Casing and presence can vary by
event type and Wazuh version, so **confirm a field against a real decoded event** (Discover →
expand the event → JSON tab) before editing a rule. In alert JSON / Discover these appear under
a `data.` prefix (`data.win.eventdata.parentImage`); inside a `<rule>` you drop the `data.`
prefix. The fixtures in [`evidence/`](evidence/) use the `data.`-prefixed (decoded-alert) shape,
which is what you see in Discover.

## Editing

`../sigma/` is the source of truth. If you change detection logic, change the Sigma rule first,
then re-port it here and update the matching fixture so `test_wazuh_rules.py` still passes.
