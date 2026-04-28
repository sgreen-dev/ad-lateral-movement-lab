# Active Directory Lateral Movement Detection Lab

A reproducible, Terraform-deployed Active Directory environment in AWS for emulating, detecting, and investigating lateral movement attacks. Logs are shipped to Wazuh, detections are authored as Sigma and translated to SPL/KQL, and findings are documented in a NIST 800-61-aligned incident report.

> **Resume bullet this lab proves:**
> *Investigated simulated lateral movement in an Active Directory environment by correlating Windows Security Events (4624 Type 3/10, 4648, 4672, 4688) and Sysmon process/network telemetry in a Wazuh SIEM; authored Sigma detection rules mapped to MITRE T1021.001/.002/.006, built triage dashboards, and documented findings in a NIST 800-61-aligned incident report. Implemented a detection-as-code CI pipeline using GitHub Actions to lint and test rules on every change.*

---

## What's in here

| Path | What it is |
|---|---|
| [`docs/`](docs/) | Incident report, architecture deep-dive, detection coverage matrix, analyst runbook |
| [`terraform/`](terraform/) | IaC for the full lab — VPC, AD hosts, Wazuh SIEM, Kali attacker, cost controls |
| [`detections/`](detections/) | Sigma rules + SPL/KQL translations + test fixtures |
| [`scripts/`](scripts/) | Windows bootstrap (Sysmon, audit policy, ART) + Python IOC parser |
| [`attack-emulation/`](attack-emulation/) | Atomic Red Team test plan with timestamps |
| [`.github/workflows/`](.github/workflows/) | Detection-as-code CI: Sigma lint, rule tests, cost-runaway check |
| [`walkthrough/`](walkthrough/) | Video walkthrough script + recording link |

---

## Architecture

```
                         AWS VPC 10.0.0.0/16  (us-east-1)
   ┌─────────────────────────────────────────────────────────────────┐
   │  Public Subnet 10.0.1.0/24                                      │
   │  ┌──────────────────────┐                                       │
   │  │  Kali (Attacker)     │   t3.medium                           │
   │  │  10.0.1.10           │   Atomic Red Team                     │
   │  └──────────┬───────────┘                                       │
   │             │ RDP / SMB / WinRM                                 │
   │             ▼                                                   │
   │  Private Subnet 10.0.2.0/24                                     │
   │  ┌──────────────────────┐    ┌──────────────────────┐           │
   │  │  DC01 (Domain Ctrl)  │    │  WIN01 (Member)      │           │
   │  │  Win Server 2022     │◄──►│  Win Server 2022     │           │
   │  │  Sysmon + Wazuh agt  │    │  Sysmon + Wazuh agt  │           │
   │  └──────────┬───────────┘    └──────────┬───────────┘           │
   │             └───────────┬───────────────┘                       │
   │                         ▼                                       │
   │  ┌──────────────────────────────────────┐                       │
   │  │  Wazuh All-in-One (Manager+Indexer)  │  t3.large             │
   │  └──────────────────────────────────────┘                       │
   └─────────────────────────────────────────────────────────────────┘
```

Full architecture details: [`docs/architecture.md`](docs/architecture.md).

---

## Detection coverage

| ATT&CK ID | Technique | Sigma rule | SPL | KQL | Tested |
|---|---|---|---|---|---|
| T1021.001 | RDP lateral movement | [`rdp_logon_unusual_source.yml`](detections/sigma/T1021.001_rdp_logon_unusual_source.yml) | ✅ | ✅ | ⏳ |
| T1021.002 | SMB / admin shares | [`admin_share_access_anomalous.yml`](detections/sigma/T1021.002_admin_share_access_anomalous.yml) | ✅ | ✅ | ⏳ |
| T1021.006 | WinRM execution | [`winrm_execution.yml`](detections/sigma/T1021.006_winrm_execution.yml) | ✅ | ✅ | ⏳ |
| T1059.001 | PowerShell post-WinRM | [`powershell_post_winrm.yml`](detections/sigma/T1059.001_powershell_post_winrm.yml) | ✅ | ✅ | ⏳ |
| Correlation | WinRM → PowerShell chain | [`correlation_winrm_to_powershell.yml`](detections/sigma/correlation_winrm_to_powershell.yml) | ✅ | ✅ | ⏳ |

ATT&CK Navigator layer: [`docs/attack-navigator-layer.json`](docs/attack-navigator-layer.json) (generated in Phase 4).

---

## Reproduce this lab

**Prerequisites:** AWS account with admin, Terraform ≥ 1.6, AWS CLI, ~$10 spend budget for a weekend.

```bash
# 1. Stand up the lab
cd terraform
terraform init
terraform apply -var="my_ip=$(curl -s ifconfig.me)/32"

# 2. Wait ~10 min for Windows hosts to bootstrap, then verify
./scripts/verify-bootstrap.sh

# 3. Run the attack chain (from Kali)
ssh -i lab-key.pem ubuntu@$(terraform output -raw kali_public_ip)
# Then follow attack-emulation/atomic-test-plan.md

# 4. Investigate the alerts in Wazuh
echo "https://$(terraform output -raw wazuh_private_ip):443"
# Tunnel via SSM port forwarding (see docs/architecture.md)

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
| 1 — Provision | 🚧 In progress |
| 2 — Instrument | ⏳ Pending |
| 3 — Attack | ⏳ Pending |
| 4 — Detect | ⏳ Pending |
| 5 — Respond | ⏳ Pending |
| 6 — Document | ⏳ Pending |

---

## Author

Built as a portfolio project demonstrating Tier 2 SOC analyst and detection engineering skills. Investigation methodology aligned to NIST SP 800-61r2; detection coverage mapped to MITRE ATT&CK and D3FEND.

## License

MIT — see [LICENSE](LICENSE). Detection rules forked from [SigmaHQ](https://github.com/SigmaHQ/sigma) retain their original DRL 1.1 license; see headers.
