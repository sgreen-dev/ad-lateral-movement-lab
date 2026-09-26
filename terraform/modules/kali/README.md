# Module: Kali

Owns the attacker host. Public-subnet, SSH-restricted to operator's IP.

## Resources created
- 1× EC2 instance (t3.medium, 30 GB root, **Ubuntu 24.04** base — no Kali repos; see note)
- Elastic IP (so you don't have to update SSH config every restart)
- Security group:
  - 22/tcp from `var.my_ip_cidr` only
  - All egress allowed (this is your attack origin)
- User data ([`bootstrap/install-kali-tools.sh`](bootstrap/install-kali-tools.sh)):
  1. apt: `nmap`, `xfreerdp` (freerdp2-x11), `hydra`, `smbclient`, plus utilities
  2. pipx: `netexec` (`nxc`, the maintained successor to CrackMapExec) and `impacket`
  3. Ruby gem: `evil-winrm`

## Outputs
- `instance_id`
- `public_ip` (the EIP)
- `private_ip` (DHCP-assigned in the public subnet — not pinned)
- `ssh_command` (`ssh -i <key>.pem ubuntu@<eip>`)
- `security_group_id`

## AMI choice
Plain Ubuntu 24.04 (`var.ami_name_pattern`, default `ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*`). The Kali rolling repo tracks Debian sid and drifts too fast to pin cleanly on Ubuntu, so tools come from Ubuntu apt, pipx and gem instead. No AWS Marketplace subscription is required.
