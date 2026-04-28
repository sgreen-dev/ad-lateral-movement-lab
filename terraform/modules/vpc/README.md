# Module: VPC

Owns the network layer of the lab.

## Resources created
- VPC (CIDR from `var.vpc_cidr`, default 10.0.0.0/16)
- 1× public subnet (10.0.1.0/24) — for Kali
- 1× private subnet (10.0.2.0/24) — for Windows hosts and Wazuh
- Internet Gateway + public route table
- NAT (Gateway or instance — TBD in Phase 1, NAT instance preferred for cost) + private route table
- Default security group hardened (no ingress, no egress)
- VPC endpoints for SSM (`com.amazonaws.<region>.ssm`, `.ssmmessages`, `.ec2messages`) — required so private Windows hosts are reachable via Session Manager without a public IP

## Outputs
- `vpc_id`
- `public_subnet_id`
- `private_subnet_id`
- `nat_egress_id` (for cost-controls reference)
