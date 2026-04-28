# Module: Windows

Owns the Active Directory plane: domain controller and member server.

## Resources created
- 2× EC2 instances (Windows Server 2022, t3.medium default) in private subnet
- IAM instance profile for SSM access
- Security groups:
  - DC: allow AD ports (53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535) from VPC; RDP/WinRM from Kali subnet only
  - Member: allow RDP/SMB/WinRM from Kali subnet and from DC subnet
- `random_password` resources for: domain admin, `alice`, `bob`, `svc_backup`, DSRM
- User data scripts (PowerShell) that:
  1. Install Sysmon with SwiftOnSecurity config (`scripts/bootstrap/install-sysmon.ps1`)
  2. Enable advanced audit policy (`scripts/bootstrap/enable-audit-policy.ps1`)
  3. Enable PowerShell ScriptBlock + Module logging
  4. (DC only) Promote to domain controller for `lab.local`
  5. (Member only) Wait for DC, then domain-join
  6. Create test users via PS DSC or post-promotion script
  7. Install Atomic Red Team (`scripts/bootstrap/install-atomic-red-team.ps1`)

## Outputs
- `dc_instance_id`, `dc_private_ip`
- `member_instance_id`, `member_private_ip`
- `domain_admin_password` (sensitive)
- `bob_password`, `svc_backup_password` (sensitive)

## Notes
- AMI lookup via `aws_ami` data source filtering on `Windows_Server-2022-English-Full-Base-*`
- `user_data` is constrained to ~16KB; longer bootstrap is split into stages with the second stage pulled from S3 if needed
