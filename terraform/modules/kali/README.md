# Module: Kali

Owns the attacker host. Public-subnet, SSH-restricted to operator's IP.

## Resources created
- 1× EC2 instance (t3.medium, Ubuntu 22.04 base + Kali metapackages — see note)
- Elastic IP (so you don't have to update SSH config every restart)
- Security group:
  - 22/tcp from `var.my_ip` only
  - All egress allowed (this is your attack origin)
- User data:
  1. `apt update && apt install -y` Kali metapackages (`kali-linux-headless` recommended for size)
  2. Install `xfreerdp`, `crackmapexec`, `impacket`, `evil-winrm`
  3. Optional: install Sliver C2 if you stretch into beacon emulation

## Outputs
- `instance_id`
- `public_ip` (the EIP)
- `ssh_command` (`ssh -i <key>.pem ubuntu@<eip>`)

## AMI choice
Two options, picked in Phase 1:
1. **Official Kali AMI** from AWS Marketplace — true Kali, $0 software cost but a marketplace subscribe step is required
2. **Ubuntu 22.04 + Kali repos** — simpler Terraform, slightly slower bootstrap

Default plan: option 2 (no marketplace friction). Switchable via `var.use_kali_ami`.
