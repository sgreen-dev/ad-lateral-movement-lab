# Architecture

> **Status:** reflects the Terraform in [`terraform/`](../terraform/) as built in Phase 1. Architecture PNG pending (Phase 6).

## Design goals

1. **Reproducible** — `terraform apply` from clean state, no manual steps.
2. **Cost-bounded** — auto-stop, budget alerts, default-destroy posture.
3. **Realistic enough to interview from** — real AD, real Sysmon, real SIEM ingestion paths.
4. **Safe** — Windows hosts never internet-exposed; admin access via SSM Session Manager only.

## Network topology

| Item | Value |
|---|---|
| Region | us-east-1 |
| VPC CIDR | 10.0.0.0/16 |
| Public subnet | 10.0.1.0/24 (Kali) |
| Private subnet | 10.0.2.0/24 (DC, member, Wazuh) |
| NAT egress | [fck-nat](https://fck-nat.dev/) NAT instance (`t4g.nano`, ARM64) in the public subnet — chosen over a NAT Gateway for cost |
| Admin access | SSM Session Manager + SSM port forwarding |

## Hosts

| Host | Role | Subnet | Instance type | OS |
|---|---|---|---|---|
| DC01 | Domain controller (`10.0.2.10`, static) | private | t3.medium | Win Server 2022 |
| WIN01 | Member server (target; Atomic Red Team installed here, `10.0.2.20`, static) | private | t3.medium | Win Server 2022 |
| WAZUH | All-in-one SIEM (`10.0.2.30`, static) | private | t3.large | Ubuntu 22.04 |
| KALI | Attacker (IP assigned by DHCP — `terraform output -raw kali_private_ip`) | public | t3.medium | Ubuntu 24.04; tools via apt (nmap, xfreerdp, hydra) + pipx (NetExec, Impacket) + gem (evil-winrm) |

## Logging pipeline

```
Windows host  →  Sysmon (channel: Microsoft-Windows-Sysmon/Operational)
              →  Security channel (4624, 4648, 4672, 4688, 5140, 5145)
              →  PowerShell channels (4103, 4104)
                            │
                            ▼
                  Wazuh agent (TCP/1514)
                            │
                            ▼
                Wazuh Manager  →  Indexer  →  Dashboard
```

## Identity

| Object | Purpose |
|---|---|
| Domain `lab.local` | AD forest root |
| `alice@lab.local` | Standard user |
| `bob@lab.local` | Local admin on WIN01 (target for lateral movement) |
| `svc_backup@lab.local` | Service account (used in WinRM/PS attacks) |

## Cost controls

See [`terraform/modules/cost-controls/`](../terraform/modules/cost-controls/) — Budgets alert, EventBridge auto-stop, and SNS notification.

## Diagram

ASCII version: see [README.md](../README.md). PNG version: `screenshots/00-architecture.png` (TBD).

## Threat model for the *lab itself*

- **Public Kali host** — SG allows only SSH (22/tcp) from the operator's `/32`. Kali is the only public-facing host.
- **No public RDP to Windows hosts.** Ever. Lateral-movement attacks originate from Kali → private subnet over the VPC's internal routing.
- **AWS account isolation** — run this in a dedicated sandbox AWS account, never a shared/work account.
- **Credentials** — domain credentials are lab-only and seeded via Terraform `random_password` resources, output to `terraform output -json`. They are generated once per create and persist in state across applies; they change only when the resources are destroyed/re-created (or `terraform apply -replace` is used).
