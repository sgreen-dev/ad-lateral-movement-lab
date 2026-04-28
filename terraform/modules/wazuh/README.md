# Module: Wazuh

Owns the SIEM: Wazuh all-in-one (Manager + Indexer + Dashboard) on a single Ubuntu host.

## Resources created
- 1× EC2 instance (Ubuntu 22.04, t3.large default) in private subnet
- IAM instance profile for SSM
- 50 GB gp3 EBS volume (indexer storage)
- Security group:
  - 1514/tcp (Wazuh agent comms) from private subnet
  - 1515/tcp (agent enrollment) from private subnet
  - 443/tcp (dashboard) from VPC only — accessed via SSM port forwarding, not public
- User data:
  1. Install Wazuh all-in-one via `wazuh-install.sh -a`
  2. Pre-stage custom decoders for Sysmon (Wazuh ships these but version drift happens)
  3. Pre-stage Sigma-translated rules (mounted from `/detections/wazuh/` in Phase 4)

## Outputs
- `instance_id`
- `private_ip`
- `dashboard_port_forward_command` (the `aws ssm start-session ... AWS-StartPortForwardingSession` invocation)
- `admin_password` (sensitive — extracted from `/var/ossec/api/configuration/admin/admin.json` post-install)

## Why all-in-one
For a lab with two endpoints, a distributed Wazuh deployment is overkill. All-in-one is the documented path and runs comfortably on t3.large.
