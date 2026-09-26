# Active Directory Lateral Movement Detection Lab

A reproducible, Terraform-deployed Active Directory environment in AWS for emulating, detecting, and investigating lateral movement attacks. Logs are shipped to Wazuh, detections are authored as Sigma and translated to SPL/KQL, and findings are documented in a NIST 800-61-aligned incident report.

> **Resume bullet this lab proves:**
> *Investigated simulated lateral movement in an Active Directory environment by correlating Windows Security Events (4624 Type 3/10, 5145), Sysmon process-creation telemetry, and PowerShell Script Block Logging (4104) in a Wazuh SIEM; authored Sigma detection rules mapped to MITRE T1021.001/.002/.006 and T1059.001, ported them to native Wazuh rules with a WinRM → PowerShell correlation, and documented findings in a NIST 800-61-aligned incident report. Implemented a detection-as-code CI pipeline using GitHub Actions to lint and test rules on every change.*

---

## What's in here

| Path | What it is |
|---|---|
| [`docs/`](docs/) | **[Operator guide](docs/operator-guide.md)** (run it yourself), incident report, architecture deep-dive, detection coverage matrix, analyst runbook |
| [`terraform/`](terraform/) | IaC for the full lab — VPC, AD hosts, Wazuh SIEM, Kali attacker, cost controls |
| [`detections/`](detections/) | Sigma rules (source of truth) + generated SPL/KQL + native Wazuh rule pack (`wazuh/`, rules `100210`–`100260`) with positive/negative test fixtures |
| [`scripts/`](scripts/) | SPL/KQL + ATT&CK Navigator generators (`generate_translations.py`, `generate_attack_layer.py`) + Python IOC parser (`parsers/`). Windows host bootstrap lives in [`terraform/modules/windows/bootstrap/`](terraform/modules/windows/bootstrap/) |
| [`attack-emulation/`](attack-emulation/) | Atomic Red Team test plan with timestamps |
| [`.github/workflows/`](.github/workflows/) | CI: Sigma lint + translation drift (`sigma-lint`), Wazuh rule fixture tests (`wazuh-rules`), IOC parser tests (`response-tools`), Terraform fmt/validate (`terraform`), daily cost-runaway check (`cost-check`) |
| [`walkthrough/`](walkthrough/) | Video walkthrough script (skeleton; script + recording link pending — Phase 6) |

---

## Architecture

```
                         AWS VPC 10.0.0.0/16  (us-east-1)
   ┌─────────────────────────────────────────────────────────────────┐
   │  Public Subnet 10.0.1.0/24                                      │
   │  ┌──────────────────────┐    ┌──────────────────────┐           │
   │  │  Kali (Attacker)     │    │  fck-nat instance    │ t4g.nano  │
   │  │  Ubuntu 24.04, DHCP  │    │  (private egress)    │           │
   │  └──────────┬───────────┘    └──────────────────────┘           │
   │             │ RDP / SMB / WinRM   t3.medium                     │
   │             ▼                                                   │
   │  Private Subnet 10.0.2.0/24                                     │
   │  ┌──────────────────────┐    ┌──────────────────────┐           │
   │  │  DC01 (Domain Ctrl)  │    │  WIN01 (Member)      │           │
   │  │  10.0.2.10           │◄──►│  10.0.2.20           │           │
   │  │  Win Server 2022     │    │  Win Server 2022     │           │
   │  │  Sysmon + Wazuh agt  │    │  Sysmon + Wazuh agt  │           │
   │  │                      │    │  + Atomic Red Team   │           │
   │  └──────────┬───────────┘    └──────────┬───────────┘           │
   │             └───────────┬───────────────┘                       │
   │                         ▼                                       │
   │  ┌──────────────────────────────────────┐                       │
   │  │  Wazuh All-in-One (Manager+Indexer)  │  t3.large             │
   │  │  10.0.2.30                           │                       │
   │  └──────────────────────────────────────┘                       │
   └─────────────────────────────────────────────────────────────────┘
```

Full architecture details: [`docs/architecture.md`](docs/architecture.md).

---

## Detection coverage

Legend: ✅ done · ⏳ pending · n/a not supported by that backend. **SPL** ([`detections/splunk/`](detections/splunk/)) and **KQL** ([`detections/kql/`](detections/kql/)) are generated from the Sigma source by [`scripts/generate_translations.py`](scripts/generate_translations.py); the `sigma-lint` CI job fails if a committed translation drifts from its Sigma source. **Tested** = fixture-validated: the native Wazuh rule ([`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml)) fires on its positive fixture and stays silent on its negative fixture in CI ([`test_wazuh_rules.py`](detections/wazuh/test_wazuh_rules.py), [`evidence/`](detections/wazuh/evidence/)). Live capture in a running lab is still pending.

| ATT&CK ID | Technique | Sigma rule | SPL | KQL | Tested |
|---|---|---|---|---|---|
| T1021.002 | NTLM network logon (lateral movement) | [`T1021_002_smb_lateral_movement.yml`](detections/sigma/T1021_002_smb_lateral_movement.yml) | ✅ | ✅ | ✅ |
| T1021.002 | SMB / admin shares (variant) | [`T1021.002_admin_share_access_anomalous.yml`](detections/sigma/T1021.002_admin_share_access_anomalous.yml) | ✅ | ✅ | ✅ |
| T1021.001 | RDP lateral movement | [`T1021.001_rdp_logon_unusual_source.yml`](detections/sigma/T1021.001_rdp_logon_unusual_source.yml) | ✅ | ✅ | ✅ |
| T1021.006 | WinRM execution | [`T1021.006_winrm_execution.yml`](detections/sigma/T1021.006_winrm_execution.yml) | ✅ | ✅ | ✅ |
| T1059.001 | PowerShell post-WinRM | [`T1059.001_powershell_post_winrm.yml`](detections/sigma/T1059.001_powershell_post_winrm.yml) | ✅ | ✅ | ✅ |
| T1021.006 → T1059.001 | WinRM → PowerShell chain (correlation) | [`correlation_winrm_to_powershell.yml`](detections/sigma/correlation_winrm_to_powershell.yml) | ✅ | n/a¹ | ✅ |

¹ The Kusto/KQL backend does not support Sigma correlation rules, so no KQL is generated for the correlation rule; its two base rules each still have standalone KQL.

All five base rules plus the correlation rule are finalized (real UUIDs, documented false-positive profiles) and convert cleanly to SPL. Five are `status: test`; the NTLM network-logon rule is still `status: experimental`. Each has a native Wazuh counterpart (`100210`–`100260`) validated against positive/negative fixtures in CI. None has yet been observed firing in a live lab run; the incident report and test-plan results are clearly-labeled exemplars. The ATT&CK Navigator coverage layer is generated from rule tags into [`docs/attack-navigator-layer.json`](docs/attack-navigator-layer.json).

---

## Reproduce this lab

**Prerequisites:** dedicated sandbox AWS account with admin (this lab authenticates via IAM Identity Center/SSO profile `lab-sso` — no static keys), Terraform ≥ 1.6, AWS CLI v2, ~$10 spend budget for a weekend.

> **Running it hands-on?** The [**Operator guide**](docs/operator-guide.md) is the full
> copy-paste runbook — start the lab, check every server's health, run any Atomic Red Team test,
> capture its telemetry, and build the matching Wazuh detection. The quick-start below is the
> 60-second version.

```bash
# 0. Sign in (SSO) and confirm you're in the lab account
export AWS_PROFILE=lab-sso          # PowerShell: $env:AWS_PROFILE = 'lab-sso'
aws sso login --sso-session lab
aws sts get-caller-identity         # Account must be the lab sandbox account

# 1. Stand up the lab
cd terraform
terraform init
terraform apply -var="my_ip=$(curl -s ifconfig.me)/32"

# 2. Wait ~10 min for Windows hosts to bootstrap, then confirm the
#    domain-join / agent-enrollment transcripts landed on the hosts:
#    C:\bootstrap-*.log on DC01 and WIN01 (view via SSM Session Manager)

# 3. Run the attack chain (from Kali)
ssh -i lab-key.pem ubuntu@$(terraform output -raw kali_public_ip)
# Then follow attack-emulation/atomic-test-plan.md

# 4. Investigate the alerts in Wazuh (private IP only — reach it through an SSM tunnel)
terraform output -raw wazuh_dashboard_command   # run the printed command, then browse https://localhost:8443
# (full steps: docs/operator-guide.md §4)

# 5. Tear down (do this every session — see cost section)
terraform destroy
```

---

## Cost discipline

This lab costs **~$165/month** if left running 24/7 and **~$5–8 per active weekend** if you discipline teardown. The Terraform stack includes:

- AWS Budgets alert at $25/month → SNS email
- EventBridge rule auto-stopping all lab instances nightly at 03:00 UTC
- GitHub Actions daily cost-runaway check ([`.github/workflows/cost-check.yml`](.github/workflows/cost-check.yml))

**Always run `terraform destroy` at end of session.** The auto-stop is a safety net, not a substitute.

---

## Status

| Phase | Status |
|---|---|
| 1 — Provision | ✅ Complete |
| 2 — Instrument | ✅ Complete |
| 3 — Attack | ✅ Complete |
| 4 — Detect | ✅ Complete |
| 5 — Respond | ✅ Complete — [IOC parser](scripts/parsers/sysmon_ioc_extractor.py) (Sysmon → Markdown/STIX) + [NIST 800-61 incident report](docs/incident-report.md) (lab exemplar) |
| 6 — Document | 🚧 In progress — operator guide, architecture, coverage matrix, and analyst runbook written; architecture PNG and video walkthrough pending |

---

## Author

Built as a portfolio project demonstrating Tier 2 SOC analyst and detection engineering skills. Investigation methodology aligned to NIST SP 800-61r2; detection coverage mapped to MITRE ATT&CK and D3FEND.

## License

MIT — see [LICENSE](LICENSE). Detection rules are authored for this lab (none are forked); where a rule's patterns follow established [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, its `references:` block cites them.
