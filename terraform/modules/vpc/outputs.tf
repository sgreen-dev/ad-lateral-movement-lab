# =============================================================================
# Outputs — VPC module
# =============================================================================

output "vpc_id" {
  description = "ID of the lab VPC."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "CIDR of the lab VPC."
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_id" {
  description = "Public subnet ID — Kali and NAT live here."
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID — Windows hosts and Wazuh live here."
  value       = aws_subnet.private.id
}

output "nat_instance_id" {
  description = "Instance ID of the fck-nat NAT instance. Cost-controls module references this for auto-stop."
  value       = aws_instance.nat.id
}

output "nat_eni_id" {
  description = "Primary ENI of the NAT instance — referenced by the private route table."
  value       = aws_instance.nat.primary_network_interface_id
}

output "vpc_endpoint_security_group_id" {
  description = "SG attached to interface endpoints. Other modules don't need this; exposed for debugging."
  value       = aws_security_group.vpc_endpoints.id
}
