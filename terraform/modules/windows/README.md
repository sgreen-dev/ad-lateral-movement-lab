# Module: Windows

Owns the Active Directory plane: domain controller and member server.

## Resources created
- 2× EC2 instances (Windows Server 2022, t3.medium default) in private subnet, static IPs:
  - DC01 `10.0.2.10` (domain controller for `lab.local`)
  - WIN01 `10.0.2.20` (member server; lateral-movement target)
- IAM instance profile for SSM access + read access to the bootstrap bucket
- S3 bucket (encrypted, public access blocked) holding the bootstrap scripts
- Security groups:
  - DC: AD ports (53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535) from VPC; RDP/WinRM from Kali subnet only
  - Member: RDP (3389), SMB (445), WinRM (5985-5986), RPC (135, 49152-65535) from VPC — the T1021.001/.002/.006 vectors
- `random_password` resources for: domain admin, `alice`, `bob`, `svc_backup`, DSRM

## Bootstrap
`user_data` is a small stub ([`bootstrap/00-userdata-stub.ps1.tftpl`](bootstrap/00-userdata-stub.ps1.tftpl)) that pulls the real scripts from S3 and runs them, working around the 16 KB `user_data` limit. Progress is tracked with `.done` state markers so the scripts survive reboots and are idempotent.

| Script | Runs on | Does |
|---|---|---|
| [`10-common.ps1`](bootstrap/10-common.ps1) | both | Defender exclusion for `C:\AtomicRedTeam`, Sysmon (SwiftOnSecurity config), advanced audit policy, PowerShell ScriptBlock + Module logging, Wazuh agent |
| [`20-promote-dc.ps1`](bootstrap/20-promote-dc.ps1) | DC01 | Promote to DC for `lab.local` (reboots), then create `alice`, `bob`, `svc_backup` with `New-ADUser` |
| [`30-domain-join.ps1`](bootstrap/30-domain-join.ps1) | WIN01 | Wait for DC SRV records, domain-join (reboots), then add `bob` to local Administrators, enable SMB-In, arm the ART install |
| [`40-install-art.ps1`](bootstrap/40-install-art.ps1) | WIN01 | Install Invoke-AtomicRedTeam + atomics to `C:\AtomicRedTeam` |

## Outputs
- `dc_instance_id`, `dc_private_ip`
- `member_instance_id`, `member_private_ip`
- `bootstrap_bucket`
- `domain_name`, `domain_admin_username`
- `domain_admin_password`, `dsrm_password` (sensitive)
- `alice_password`, `bob_password`, `svc_backup_password` (sensitive)
- `dc_ssm_command`, `member_ssm_command`
- `dc_rdp_port_forward`, `member_rdp_port_forward`

## Notes
- AMI lookup via `aws_ami` data source filtering on `Windows_Server-2022-English-Full-Base-*`
- Passwords are generated once and kept in Terraform state; they change only when the instances are destroyed and re-created.
