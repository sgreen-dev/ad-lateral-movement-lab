# =============================================================================
# Outputs — Wazuh module
# =============================================================================

output "instance_id" {
  description = "Wazuh SIEM instance ID."
  value       = aws_instance.wazuh.id
}

output "private_ip" {
  description = "Wazuh manager private IP. Pass this to the Windows module's wazuh_manager_ip variable for agent enrollment."
  value       = aws_instance.wazuh.private_ip
}

output "security_group_id" {
  description = "Wazuh SG ID. Cost-controls module references this for tagged stop."
  value       = aws_security_group.wazuh.id
}

output "dashboard_port_forward_command" {
  description = "Run this from your laptop to tunnel the dashboard, then visit https://localhost:8443"
  value       = "aws ssm start-session --target ${aws_instance.wazuh.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443"
}

output "ssm_session_command" {
  description = "Open a shell on the Wazuh host (e.g., to retrieve the admin password from /etc/wazuh-install-files/wazuh-passwords.txt)."
  value       = "aws ssm start-session --target ${aws_instance.wazuh.id}"
}
