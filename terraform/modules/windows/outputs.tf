# =============================================================================
# Outputs — Windows module
# =============================================================================

output "dc_instance_id" {
  description = "DC01 instance ID."
  value       = aws_instance.dc.id
}

output "dc_private_ip" {
  description = "DC01 private IP (static, 10.0.2.10)."
  value       = aws_instance.dc.private_ip
}

output "member_instance_id" {
  description = "WIN01 instance ID."
  value       = aws_instance.member.id
}

output "member_private_ip" {
  description = "WIN01 private IP (static, 10.0.2.20)."
  value       = aws_instance.member.private_ip
}

output "bootstrap_bucket" {
  description = "S3 bucket holding bootstrap scripts. Useful for debugging if a host fails to bootstrap."
  value       = aws_s3_bucket.bootstrap.id
}

output "domain_name" {
  description = "AD domain FQDN."
  value       = var.domain_name
}

# --- Sensitive credential outputs ---
# Retrieve any of these with: terraform output -raw <name>

output "domain_admin_username" {
  value       = "Administrator"
  description = "Local Administrator on the DC, becomes Domain Admin after promotion."
}

output "domain_admin_password" {
  value     = random_password.domain_admin.result
  sensitive = true
}

output "dsrm_password" {
  value     = random_password.dsrm.result
  sensitive = true
}

output "alice_password" {
  value     = random_password.alice.result
  sensitive = true
}

output "bob_password" {
  value     = random_password.bob.result
  sensitive = true
}

output "svc_backup_password" {
  value     = random_password.svc_backup.result
  sensitive = true
}

# --- Connection commands for convenience ---

output "dc_ssm_command" {
  description = "Open an SSM session to DC01."
  value       = "aws ssm start-session --target ${aws_instance.dc.id}"
}

output "member_ssm_command" {
  description = "Open an SSM session to WIN01."
  value       = "aws ssm start-session --target ${aws_instance.member.id}"
}

output "dc_rdp_port_forward" {
  description = "Tunnel RDP to DC01 via SSM. After running, RDP to localhost:13389."
  value       = "aws ssm start-session --target ${aws_instance.dc.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=13389"
}

output "member_rdp_port_forward" {
  description = "Tunnel RDP to WIN01 via SSM. After running, RDP to localhost:23389."
  value       = "aws ssm start-session --target ${aws_instance.member.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3389,localPortNumber=23389"
}
