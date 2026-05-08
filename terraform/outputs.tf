# =============================================================================
# Top-level outputs
# =============================================================================
# Bubbled up from modules so you can run `terraform output <name>` from the
# repo root without diving into module state.
# =============================================================================


# --- Connection info ---

output "kali_public_ip" {
  description = "Kali Elastic IP. SSH target."
  value       = module.kali.public_ip
}

output "kali_ssh_command" {
  description = "Ready-to-paste SSH command. Replace <key.pem> with your key file path."
  value       = module.kali.ssh_command
}

output "kali_private_ip" {
  description = "Kali private IP. This is the source IP that appears in Windows event logs (4624 IpAddress field) when Kali attacks land."
  value       = module.kali.private_ip
}

output "wazuh_dashboard_command" {
  description = "Run on your laptop to tunnel the dashboard, then visit https://localhost:8443"
  value       = module.wazuh.dashboard_port_forward_command
}

output "wazuh_ssm_command" {
  description = "Open a shell on the Wazuh host (e.g., to retrieve admin password)."
  value       = module.wazuh.ssm_session_command
}

output "wazuh_private_ip" {
  description = "Wazuh manager private IP — agents auto-enrolled against this on bootstrap."
  value       = module.wazuh.private_ip
}

output "dc_ssm_command" {
  description = "Open an SSM shell on DC01."
  value       = module.windows.dc_ssm_command
}

output "dc_rdp_port_forward" {
  description = "Tunnel RDP to DC01. Then RDP to localhost:13389."
  value       = module.windows.dc_rdp_port_forward
}

output "member_ssm_command" {
  description = "Open an SSM shell on WIN01."
  value       = module.windows.member_ssm_command
}

output "member_rdp_port_forward" {
  description = "Tunnel RDP to WIN01. Then RDP to localhost:23389."
  value       = module.windows.member_rdp_port_forward
}


# --- IPs (for reference / runbook population) ---

output "dc_private_ip" {
  description = "DC01 private IP (static, 10.0.2.10)."
  value       = module.windows.dc_private_ip
}

output "member_private_ip" {
  description = "WIN01 private IP (static, 10.0.2.20)."
  value       = module.windows.member_private_ip
}


# --- Sensitive credentials ---
# Retrieve any of these with:  terraform output -raw <name>

output "domain_admin_password" {
  description = "Local Administrator on DC, becomes Domain Admin after promotion. Use 'terraform output -raw domain_admin_password' to retrieve."
  value       = module.windows.domain_admin_password
  sensitive   = true
}

output "alice_password" {
  description = "Standard user. Use 'terraform output -raw alice_password' to retrieve."
  value       = module.windows.alice_password
  sensitive   = true
}

output "bob_password" {
  description = "Local admin on WIN01. Used for T1021.001 (RDP) and T1021.002 (SMB) attacks."
  value       = module.windows.bob_password
  sensitive   = true
}

output "svc_backup_password" {
  description = "Service account in Remote Management Users. Used for T1021.006 (WinRM) attacks."
  value       = module.windows.svc_backup_password
  sensitive   = true
}


# --- Operational references ---

output "bootstrap_bucket" {
  description = "S3 bucket holding Windows bootstrap scripts. Useful if a host fails to bootstrap and you need to inspect."
  value       = module.windows.bootstrap_bucket
}

output "autostop_test_command" {
  description = "Manually invoke the auto-stop Lambda to test it."
  value       = module.cost_controls.test_lambda_command
}

output "sns_topic_arn" {
  description = "SNS topic for cost alerts. Confirm your subscription via the email AWS sends on first apply."
  value       = module.cost_controls.sns_topic_arn
}
