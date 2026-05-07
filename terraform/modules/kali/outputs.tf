# =============================================================================
# Outputs — Kali module
# =============================================================================

output "instance_id" {
  description = "Kali instance ID."
  value       = aws_instance.kali.id
}

output "public_ip" {
  description = "Kali Elastic IP. SSH target."
  value       = aws_eip.kali.public_ip
}

output "private_ip" {
  description = "Kali private IP. Source IP visible in Windows event logs (4624 IpAddress field)."
  value       = aws_instance.kali.private_ip
}

output "ssh_command" {
  description = "Ready-to-paste SSH command. Replace <key.pem> with your key file path."
  value       = "ssh -i <key.pem> ubuntu@${aws_eip.kali.public_ip}"
}

output "security_group_id" {
  description = "Kali SG ID."
  value       = aws_security_group.kali.id
}
