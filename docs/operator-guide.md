# Operator Guide — Run the Lab Yourself

| | |
|---|---|
| **Owner** | Shurron Green |
| **Last reviewed** | 2026-08-20 |
| **Version** | 1.0 |
| **Review cadence** | Re-verify after any change to `terraform/` or the bootstrap scripts |
| **Escalation** | Solo lab — you are the operator and the owner. Cost anomalies → AWS Budgets alert ($25) + SNS email; runaway instances → §8 teardown. |

> **Purpose:** stand the lab up, confirm every server is healthy, pick *any* Atomic Red Team
> test, run it, and capture + detect its telemetry in Wazuh — without following a script.
>
> This is the *operator loop*. The canonical attack chain lives in
> [`attack-emulation/atomic-test-plan.md`](../attack-emulation/atomic-test-plan.md); the
> analyst triage side lives in [`runbook-lateral-movement.md`](runbook-lateral-movement.md).

### Shell conventions (read once)

Commands are labelled by **where you run them**:

| Block label | Where | Shell |
|---|---|---|
| ```powershell``` under "your laptop" | Your Windows machine | **PowerShell 7+** (your primary shell). A `# bash:` note follows where the Git-Bash/Linux form differs. |
| ```powershell``` under "on WIN01 / DC01" | Windows host, via SSM | PowerShell (SSM lands you in it) |
| ```bash``` under "on Wazuh / Kali" | Ubuntu host, via SSM or SSH | bash |

`lab-key.pem` in the examples is the private key for the EC2 key pair **`lab-key`** (set in
`terraform.tfvars`). Keep it in the repo root (it is gitignored) or `~/.ssh/`; examples assume
repo root.

## Host cheat-sheet

| Host | Name tag | Role | IP | Reach it via |
|---|---|---|---|---|
| **Kali** | `ad-lateral-movement-lab-kali` | Attacker | `10.0.1.10` (public EIP) | `ssh -i lab-key.pem ubuntu@$KALI_IP` |
| **DC01** | `ad-lateral-movement-lab-dc01` | Domain controller (`lab.local`) | `10.0.2.10` | SSM session / RDP tunnel `localhost:13389` |
| **WIN01** | `ad-lateral-movement-lab-win01` | Member server + **Atomic Red Team host** | `10.0.2.20` | SSM session / RDP tunnel `localhost:23389` |
| **WAZUH** | `ad-lateral-movement-lab-wazuh` | SIEM (manager+indexer+dashboard) | private | SSM session / dashboard tunnel `https://localhost:8443` |

Domain accounts (passwords via `terraform output -raw <name>`):

| Account | Role | Used for |
|---|---|---|
| `Administrator` | Domain Admin | break-glass |
| `lab\alice` | standard user | benign baseline noise |
| `lab\bob` | local admin on WIN01 | RDP (T1021.001), SMB (T1021.002) |
| `lab\svc_backup` | Remote Management Users | WinRM (T1021.006) |

> **Where do atomics run?** Invoke-AtomicRedTeam is installed on **WIN01 only**
> (`C:\AtomicRedTeam`). Run single-host atomics on WIN01. For the cross-host
> lateral-movement tests, the *source* is Kali or DC01 and the *target/telemetry* is WIN01.

---

## 0. One-time prerequisites (your laptop)

```powershell
aws sts get-caller-identity          # correct AWS account? (use a dedicated sandbox account)
terraform version                    # >= 1.6
aws --version                        # AWS CLI v2
session-manager-plugin --version     # required for every 'aws ssm start-session'
```

If any of the four errors out, fix that before going further — the rest of the guide assumes
all four are on PATH.

`terraform/terraform.tfvars` is already filled (`my_ip`, `key_pair_name = lab-key`,
`alert_email`). If your public IP changed since last session, refresh it — the Kali security
group only admits your `/32`:

```powershell
cd terraform
$ip = (Invoke-RestMethod "https://ifconfig.me/ip").Trim()
(Get-Content terraform.tfvars) -replace '^my_ip\s*=.*', "my_ip = `"$ip/32`"" | Set-Content terraform.tfvars
Select-String '^my_ip' terraform.tfvars     # verify it now shows your current /32
# bash: sed -i "s#^my_ip.*#my_ip = \"$(curl -s ifconfig.me)/32\"#" terraform.tfvars
```

---

## 1. Start the lab

```powershell
cd terraform
terraform init                       # first time / after module changes only
terraform plan -out tfplan
terraform apply tfplan
```

Provisioning takes **~10–15 min**. Instances boot in ~2 min, then the Windows hosts run their
bootstrap chain (promote DC → domain-join WIN01 → Sysmon → audit policy → PowerShell logging →
Wazuh agent → install ART) and Wazuh runs its all-in-one installer. **Do not attack until §2
reports all-green.**

### 1b. Capture session handles (run once per session, from `terraform/`)

There is no root-level instance-id output, so resolve the IDs from the ready-made SSM command
outputs into variables you'll reuse all session:

```powershell
$WIN01_ID = ((terraform output -raw member_ssm_command) -replace '.*--target\s+','').Trim()
$DC01_ID  = ((terraform output -raw dc_ssm_command)     -replace '.*--target\s+','').Trim()
$WAZUH_ID = ((terraform output -raw wazuh_ssm_command)  -replace '.*--target\s+','').Trim()
$KALI_IP  =  (terraform output -raw kali_public_ip).Trim()
$WIN01_ID, $DC01_ID, $WAZUH_ID, $KALI_IP     # sanity-print: expect i-..., i-..., i-..., an IP
```

Passwords stay in Terraform state — pull them on demand, don't stash them in variables:

```powershell
terraform output -raw bob_password           # also: alice_password, svc_backup_password, domain_admin_password
```

> These variables live only in the current PowerShell session. Re-run 1b after opening a new
> terminal. (New terminal in bash? Re-export the same handles with the `# bash:` forms.)

---

## 2. Check server status (every session, before attacking)

### 2a. Are the four instances running?

```powershell
aws ec2 describe-instances --filters "Name=tag:Project,Values=ad-lateral-movement-lab" "Name=instance-state-name,Values=running" --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,State.Name,PrivateIpAddress]' --output table
```

**Known-good output** — exactly **4** rows:

```
------------------------------------------------------------------------------
|                             DescribeInstances                              |
+---------------------------------+-----------------------+---------+---------+
|  ad-lateral-movement-lab-kali   |  i-0a1b...            | running | 10.0.1.10 |
|  ad-lateral-movement-lab-dc01   |  i-0c3d...            | running | 10.0.2.10 |
|  ad-lateral-movement-lab-win01  |  i-0e5f...            | running | 10.0.2.20 |
|  ad-lateral-movement-lab-wazuh  |  i-0g7h...            | running | 10.0.x.x  |
+---------------------------------+-----------------------+---------+---------+
```

**Fewer than 4 rows?** The nightly auto-stop (03:00 UTC) likely stopped them. Start them:

```powershell
$ids = (aws ec2 describe-instances --filters "Name=tag:Project,Values=ad-lateral-movement-lab" --query 'Reservations[].Instances[].InstanceId' --output text)
aws ec2 start-instances --instance-ids $ids.Split()
# Then re-run 2a until all 4 read "running", and re-run 1b (instance IDs are stable across stop/start).
```

If a host is entirely **absent** from `describe-instances` (not just stopped), Terraform never
created it — check `terraform state list` and re-`apply`.

### 2b. Did the Windows hosts finish bootstrapping?

Open a PowerShell shell on WIN01 (SSM lands you in **PowerShell as `NT AUTHORITY\SYSTEM`**):

```powershell
aws ssm start-session --target $WIN01_ID
```

Then, on WIN01:

```powershell
# Bootstrap step markers — expect 6 .done files (defender, sysmon, auditpol, pslogging, wazuh, art)
Get-ChildItem C:\bootstrap-state
Get-Content C:\bootstrap-common.log -Tail 40    # tail transcripts if any marker is missing
Get-Content C:\bootstrap-art.log    -Tail 20

# Telemetry sources live? Both services must read "Running".
Get-Service Sysmon64, WazuhSvc | Format-Table Name, Status, StartType
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational | Select-Object LogName, RecordCount, IsEnabled
auditpol /get /category:* | Select-String "Process Creation|Logon|File Share"   # each should show "Success" (+ Failure where set)

# ART ready?
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
(Invoke-AtomicTest All -ShowDetailsBrief | Measure-Object).Count
```

**Acceptance:** `Sysmon64` and `WazuhSvc` both `Running`; Sysmon `RecordCount` non-zero and
rising; audit subcategories show `Success`; ART count **> 1000** (the full atomics library).
A count **< 100** means the ART install is broken — the bootstrap itself warns below 100; see
`C:\bootstrap-art.log` and Troubleshooting.

Repeat 2b on **DC01** (`aws ssm start-session --target $DC01_ID`) only if you'll launch WinRM
from there. ART is intentionally **not** installed on DC01.

### 2c. Is Wazuh healthy and are both agents reporting?

```bash
# On the Wazuh host  (aws ssm start-session --target $WAZUH_ID)
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard   # want three lines, all "active"
sudo /var/ossec/bin/agent_control -l                                  # DC01 + WIN01 must be "Active"
```

**Known-good `agent_control -l`:**

```
Wazuh agent_control. List of available agents:
   ID: 001, Name: WIN01, IP: 10.0.2.20, Active
   ID: 002, Name: DC01,  IP: 10.0.2.10, Active
```

Retrieve the dashboard login (format varies slightly across Wazuh 4.x point releases — read the
whole file and find the block whose user is `admin`; that's the dashboard/API login):

```bash
sudo cat /etc/wazuh-install-files/wazuh-passwords.txt
#   look for:  User: 'admin'   /   Password: '...'
```

Any service not `active`, or an agent showing **Never connected / Disconnected** →
[Troubleshooting](#troubleshooting).

### 2d. End-to-end ingest sanity (30-second smoke test)

On **WIN01**, emit one unmistakable event:

```powershell
$stamp = "LABTEST-$([guid]::NewGuid().ToString('N').Substring(0,8))"
Write-Host $stamp        # emits PowerShell ScriptBlock event 4104 carrying your unique marker
$stamp                   # copy this value
```

Then in Wazuh Discover (§4) search `full_log: *LABTEST*` over the last 5 minutes. **Land the
event → pipeline is live end-to-end and you're clear to run atomics.** No hit after 2 min →
agent/ingest is broken; see Troubleshooting before wasting an attack run.

---

## 3. Get onto the boxes

```powershell
# Attacker (Kali) — from your laptop
ssh -i lab-key.pem ubuntu@$KALI_IP

# Windows shell (PowerShell as SYSTEM) — no public RDP, SSM only
aws ssm start-session --target $WIN01_ID

# Interactive Windows desktop (RDP): tunnel first, then point an RDP client at localhost.
#   DC01 -> localhost:13389    WIN01 -> localhost:23389
aws ssm start-session --target $WIN01_ID --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=23389
# then, in another window:  mstsc /v:localhost:23389   (login lab\bob, password from: terraform output -raw bob_password)
```

Prefer the ready-made outputs? `terraform output -raw member_rdp_port_forward` (and
`dc_rdp_port_forward`, `wazuh_dashboard_command`) print the exact tunnel command with the ID
already substituted.

---

## 4. Open Wazuh and find your data

From your laptop, start the dashboard tunnel and leave it running in its own terminal:

```powershell
aws ssm start-session --target $WAZUH_ID --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443
```

Browse to **https://localhost:8443** (accept the self-signed cert — expected) → log in as
`admin` with the password from §2c → hamburger menu → **Discover**.

### Where telemetry lives — two indexes

| Index pattern | Contains | Use it for |
|---|---|---|
| `wazuh-alerts-*` | Events that **matched a Wazuh rule** (on by default) | "Did anything fire?" triage |
| `wazuh-archives-*` | **Every** event, matched or not (only if archive logging is on) | "Show me the raw telemetry" — the full picture |

By default Wazuh indexes only *alerts*. Many atomics produce Sysmon/Security events that don't
trip a built-in rule, so they won't show in `wazuh-alerts-*`. To see **all** raw telemetry
(recommended for this lab), enable archives once on the Wazuh manager:

```bash
# On the Wazuh host. Inside <global> of /var/ossec/etc/ossec.conf set BOTH:
#   <logall>yes</logall>   and   <logall_json>yes</logall_json>
sudo sed -i 's#<logall>no</logall>#<logall>yes</logall>#; s#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf

# VERIFY the edit took (whitespace in the file can defeat the sed — must print two "yes" lines):
grep -E '<logall(_json)?>' /var/ossec/etc/ossec.conf

sudo systemctl restart wazuh-manager

# Enable the archives index in Filebeat: edit /etc/filebeat/modules.d/wazuh.yml,
# under "archives:" set "enabled: true", then:
sudo systemctl restart filebeat

# CONFIRM archives are being written (file should exist and grow as events arrive):
sudo tail -f /var/ossec/logs/archives/archives.json
```

In Discover, add the `wazuh-archives-*` index pattern (Stack Management → Index Patterns →
Create, time field `timestamp`) and query against it for full-fidelity telemetry.

> **Cost/footprint:** archives roughly **doubles** index storage — fine for a weekend on the
> t3.large, but disable it when you're done exploring. **Revert:** set both flags back to `no`,
> `sudo systemctl restart wazuh-manager filebeat`.

### Field cheat-sheet (Windows eventchannel → Wazuh field names)

Wazuh decodes Windows event XML into `data.win.system.*` (envelope) and `data.win.eventdata.*`
(payload). **Verify any field against a real event before relying on it** (§7b) — decoding can
vary by event type. The ones you'll query most:

| You want | Query (DQL in Discover) |
|---|---|
| Everything from WIN01 | `agent.name: WIN01` |
| A specific event ID | `data.win.system.eventID: "1"` (Sysmon proc create) · `"4624"` · `"4688"` · `"4104"` |
| Sysmon by parent process | `data.win.eventdata.parentImage: *wsmprovhost.exe` |
| Sysmon by image / cmdline | `data.win.eventdata.image: *powershell.exe` · `data.win.eventdata.commandLine: *-enc*` |
| Network logon source IP | `data.win.eventdata.ipAddress: "10.0.1.10"` (Kali = attacker source) |
| Logon type (RDP=10, network=3) | `data.win.eventdata.logonType: "10"` |
| PowerShell script text | `data.win.system.channel: "Microsoft-Windows-PowerShell/Operational" and data.win.system.eventID: "4104"` |
| Only things that alerted | `rule.level >= 3` · by technique: `rule.mitre.id: "T1021.006"` |

**Always set the time picker** to a tight window around your test (e.g. "Last 15 minutes") so
you're reading *your* run, not history.

---

## 5. Run any atomic test (the reusable loop)

The muscle memory for grabbing a *random* atomic and driving it end to end. Do it in a
PowerShell/SSM session on **WIN01**.

> **Credential context matters.** An SSM shell runs as `NT AUTHORITY\SYSTEM`, so atomics you
> launch here execute as the **machine account** — Security 4688/4624 `SubjectUserName` will be
> `WIN01$`, not a domain user. That's fine for process/Sysmon/file telemetry. But if your
> detection keys on a *user* (e.g. `bob`, `svc_backup`), the SYSTEM context will make it look
> wrong. To generate user-context telemetry: RDP in as that user (§3), open PowerShell **in the
> RDP session**, and run `Invoke-AtomicTest` from there instead.

```powershell
# --- once per session: load the runner ---
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# --- 0. pick a technique (browse what's available) ---
Invoke-AtomicTest All -ShowDetailsBrief         # firehose; pipe to Out-GridView or Select-String
Invoke-AtomicTest T1053.005 -ShowDetailsBrief   # just this technique's tests
Invoke-AtomicTest T1053.005 -ShowDetails        # full: description, commands, cleanup, inputs

# --- 1. mark your start time (UTC) so you can find events later ---
$t0 = (Get-Date).ToUniversalTime(); "START $($t0.ToString('o'))"

# --- 2. prereqs: check, then fetch anything missing ---
Invoke-AtomicTest T1053.005 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1053.005 -TestNumbers 1 -GetPrereqs

# --- 3. RUN IT ---
Invoke-AtomicTest T1053.005 -TestNumbers 1

# --- 4. note stop time, then let events serialize into the SIEM (~60s) ---
"STOP $((Get-Date).ToUniversalTime().ToString('o'))"; Start-Sleep 60

# --- 5. ALWAYS clean up (removes files/tasks/users the test created) ---
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

**Habits that keep runs clean:**
- **One test at a time**, 60s apart — events serialize instead of interleaving.
- Read `-ShowDetails` **before** running so you know which artifacts (process, file, reg key,
  scheduled task, service, account) to expect — that list *is* your hunt list in Wazuh.
- Some `-GetPrereqs` steps download tooling that itself generates telemetry — expect it.
- Run `-Cleanup` even if the test "failed" — partial artifacts still need removing.

> **Cross-host lateral-movement tests** (the headline scenario) don't run via
> `Invoke-AtomicTest` on WIN01 — you launch them *from the source host* and read telemetry
> *on WIN01*. Exact commands + expected events are in
> [`attack-emulation/atomic-test-plan.md`](../attack-emulation/atomic-test-plan.md):
> RDP from Kali (`xfreerdp … /v:10.0.2.20`), SMB from WIN01 (`net use \\DC01\C$`),
> WinRM from DC01 (`Invoke-Command -ComputerName WIN01 …`).

---

## 6. Capture the telemetry

1. In Discover, set the time window to your `START`/`STOP` marks.
2. Scope to the target: `agent.name: WIN01`.
3. Look for the artifacts step 0 told you to expect:
   - spawned a process → `data.win.system.eventID: "1"` + filter on `data.win.eventdata.image`
   - made a network connection → Sysmon EID 3 (`data.win.system.eventID: "3"`)
   - wrote a file → Sysmon EID 11 · scheduled task → Security 4698 · service → 7045 / Sysmon 1 parent `services.exe`
   - ran PowerShell → 4104 script block text
4. **Save the evidence.** Add columns (`data.win.system.eventID`, `data.win.eventdata.image`,
   `data.win.eventdata.commandLine`), then **Share → CSV/JSON export**, or query Dev Tools:

```
GET wazuh-archives-*/_search
{ "query": { "bool": { "must": [
  { "match": { "agent.name": "WIN01" } },
  { "range": { "timestamp": { "gte": "2026-08-20T00:00:00Z", "lte": "2026-08-20T00:15:00Z" } } }
] } }, "size": 200 }
```

Save exports to `attack-emulation/raw-events.<date>.json` (gitignored — sanitize before copying
excerpts into `docs/incident-report.md`).

If you saw the raw events in `wazuh-archives-*` but **nothing in `wazuh-alerts-*`**, telemetry
is flowing but no rule matched — that's the cue for §7.

---

## 7. Build the detection in Wazuh

The repo's authoritative detections are **Sigma** (`detections/sigma/*.yml`), translated to
SPL/KQL. Wazuh doesn't ingest Sigma — you port the Sigma *logic* into a native Wazuh rule. That
translation is the detection-engineering rep.

### 7a. Read the Sigma rule as your spec

```bash
cat detections/sigma/T1021.006_winrm_execution.yml
```

The `detection:` block is the whole spec: `logsource.category: process_creation` +
`ParentImage|endswith: '\wsmprovhost.exe'`.

### 7b. Confirm the field name against a real event

Find one matching event in Discover and expand it (JSON tab) to copy the **exact** Wazuh field
path — e.g. `data.win.eventdata.parentImage`. Guessing field names is the #1 reason a custom
rule silently never fires.

### 7c. Write the custom rule on the Wazuh manager

> **The six lab rules already ship** as [`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml)
> — install them with `sudo cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/` +
> `systemctl restart wazuh-manager` (see [`detections/wazuh/README.md`](../detections/wazuh/README.md)),
> and validate the logic offline with `python detections/wazuh/test_wazuh_rules.py`. Author a
> *new* rule when you're detecting a technique the pack doesn't cover — the pattern below is the
> template (it's rule `100210` from the pack).

Custom rules go in `/var/ossec/etc/rules/local_rules.xml` (rule IDs **100000–120000** are the
user range). Sysmon Event ID 1 decodes under the built-in group `sysmon_event1`:

```xml
<group name="lateral_movement,sysmon,">
  <rule id="100210" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\wsmprovhost\.exe$</field>
    <description>T1021.006 WinRM remote execution: child of wsmprovhost.exe</description>
    <mitre>
      <id>T1021.006</id>
    </mitre>
    <group>lateral_movement,winrm_remote_execution,</group>
  </rule>
</group>
```

Notes: `type="pcre2"` makes `<field>` a PCRE2 regex — unanchored search, `(?i)` for case,
`\\` for a literal backslash, `$` to anchor the end; add `negate="yes"` to invert (used for the
allow-list filters in the shipped rules). Inside rules Wazuh drops the `data.` prefix — match
`win.eventdata.parentImage`, not `data.win...`. Level 12 = high.

### 7d. Validate, then load

```bash
# Syntax / will-it-load check. (Pasting Windows eventchannel JSON into logtest is fiddly — treat
# this as a load check; the live re-run below is the real validation.)
sudo /var/ossec/bin/wazuh-logtest -v
sudo systemctl restart wazuh-manager
```

Then **re-run the atomic from §5** and confirm the alert now appears — `rule.id: "100210"` (or
`rule.mitre.id: "T1021.006"`) in `wazuh-alerts-*`. Seeing your own rule fire on a live test is
the point — that's the true positive the README's "Tested ✅" column claims.

> **Revert a rule:** delete its `<rule>` block from `local_rules.xml`,
> `sudo systemctl restart wazuh-manager`.
>
> **Prefer SPL/KQL?** `detections/splunk/*.conf` and `detections/kql/*.kql` are generated from
> the same Sigma by `python scripts/generate_translations.py` — drop those into Splunk/Sentinel
> verbatim.

---

## 8. Tear down (every session — this is the cost discipline)

```powershell
cd terraform
terraform destroy
```

The nightly auto-stop (03:00 UTC) and the $25 budget alert are **safety nets, not a substitute**
for destroy. Left running 24/7 this stack is ~$165/mo; disciplined teardown keeps a weekend to
~$5–8. Confirm nothing lingers:

```powershell
aws ec2 describe-instances --filters "Name=tag:Project,Values=ad-lateral-movement-lab" "Name=instance-state-name,Values=running" --query 'Reservations[].Instances[].InstanceId' --output text
# Expect no output. Any instance ID printed = still billing; investigate before you walk away.
```

> If you enabled archives (§4) and plan to `destroy` anyway, no cleanup is needed — the whole
> host goes with it. If you only *stopped* the lab (not destroyed), disable archives to cap disk
> growth while it's parked.

---

## The whole loop, condensed

```
terraform apply + 1b                 # §1  stand up, capture $WIN01_ID/$DC01_ID/$WAZUH_ID/$KALI_IP
check status (2a–2d)                 # §2  4 running · services active · agents Active · smoke test passes
pick atomic + $t0                    # §5  Invoke-AtomicTest <Txxxx> -ShowDetails
CheckPrereqs / GetPrereqs / run      # §5  execute (mind SYSTEM vs user context)
wait 60s · Cleanup                   # §5  serialize + clean
Discover: agent.name + time window   # §6  capture raw telemetry
  fired in wazuh-alerts-*?  -> triage with runbook-lateral-movement.md
  only in wazuh-archives-*? -> §7 write the Wazuh rule, restart, re-run, confirm
terraform destroy                    # §8  every session
```

---

## Troubleshooting

| Symptom | Check |
|---|---|
| SSH to Kali times out | Public IP changed → refresh `my_ip` (§0) and `terraform apply` (updates the SG). |
| `start-session` fails | SSM needs the instance's IAM profile + the plugin on your laptop; instance must be `running` and SSM-healthy (`aws ssm describe-instance-information`). |
| `$WIN01_ID` etc. empty | You're not in `terraform/`, or apply hasn't completed. Re-run 1b from the `terraform/` dir. |
| Windows host never finished bootstrap | SSM in → `Get-Content C:\bootstrap-*.log -Tail 60`; missing `.done` markers in `C:\bootstrap-state` show which step died. |
| Agent "Never connected" | On WIN01: `Get-Service WazuhSvc` (start it if stopped); on Wazuh: `sudo /var/ossec/bin/agent_control -l`, and check the manager is reachable on 1514 from the agent subnet. |
| Atomic ran but no Sysmon events | `Get-Service Sysmon64`; `Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational` RecordCount should be rising. |
| ART count < 100 | Install broke — `Get-Content C:\bootstrap-art.log -Tail 40`; re-run `Install-AtomicRedTeam -getAtomics -Force`. |
| Events in archives but no alert | Expected for benign atomics — no built-in rule matched. Write the rule (§7). |
| `wazuh-archives-*` empty after enabling | Re-check the `grep` verify in §4 (sed may have missed on whitespace); confirm `filebeat` restarted; `sudo filebeat test output`. |
| Nothing in Wazuh at all | Time window too narrow? Wrong index pattern? Agent disconnected? Run the §2d smoke test to isolate the break. |
| Dashboard cert warning | Expected (self-signed). Proceed past it. |
