# Module: Wazuh

Owns the SIEM: Wazuh all-in-one (Manager + Indexer + Dashboard) on a single Ubuntu host.

## Resources created
- 1× EC2 instance (Ubuntu 22.04, t3.large default) in private subnet, static IP `10.0.2.30`
- IAM instance profile for SSM
- 50 GB gp3 root volume (`var.data_volume_size_gb`; holds indexer storage)
- Security group (all ingress from the VPC CIDR only):
  - 1514/tcp (Wazuh agent comms)
  - 1515/tcp (agent enrollment)
  - 55000/tcp (Wazuh API)
  - 443/tcp (dashboard) — accessed via SSM port forwarding, not public
- User data ([`bootstrap/install-wazuh.sh.tftpl`](bootstrap/install-wazuh.sh.tftpl)):
  1. System prep (apt prerequisites)
  2. Install Wazuh all-in-one via `wazuh-install.sh -a` (version `var.wazuh_version`)
  3. Verify the shipped Sysmon ruleset is present and restart the manager
  4. Health-check `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`

The lab's custom rule pack ([`detections/wazuh/local_rules.xml`](../../../detections/wazuh/local_rules.xml), rules `100210`–`100260`) is **not** deployed by user data — install it manually per [`detections/wazuh/README.md`](../../../detections/wazuh/README.md).

## Outputs
- `instance_id`
- `private_ip`
- `security_group_id`
- `dashboard_port_forward_command` (the `aws ssm start-session ... AWS-StartPortForwardingSession` invocation)
- `ssm_session_command`

The dashboard `admin` password is not a Terraform output. Read it on the host from `/etc/wazuh-install-files/wazuh-passwords.txt` (via `ssm_session_command`).

## Why all-in-one
For a lab with two endpoints, a distributed Wazuh deployment is overkill. All-in-one is the documented path and runs comfortably on t3.large.
