# Module: VPC

Owns the network layer of the lab.

## Resources created
- VPC (CIDR from `var.vpc_cidr`, default 10.0.0.0/16)
- 1× public subnet (`var.public_subnet_cidr`, default 10.0.1.0/24) — for Kali and the NAT instance
- 1× private subnet (`var.private_subnet_cidr`, default 10.0.2.0/24) — for Windows hosts and Wazuh
- Internet Gateway + public route table
- [fck-nat](https://fck-nat.dev/) NAT **instance** (`var.nat_instance_type`, default `t4g.nano`, ARM) + private route table — chosen over a NAT Gateway for cost; stopped nightly by cost-controls
- Default security group hardened (no ingress, no egress)
- VPC endpoints: SSM interface trio (`.ssm`, `.ssmmessages`, `.ec2messages`) + free S3 gateway endpoint — required so private Windows hosts are reachable via Session Manager without a public IP

## Outputs
- `vpc_id`
- `vpc_cidr`
- `public_subnet_id`
- `private_subnet_id`
- `nat_instance_id` (for cost-controls reference)
- `nat_eni_id`
- `vpc_endpoint_security_group_id`
