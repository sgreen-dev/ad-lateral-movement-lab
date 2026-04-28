# =============================================================================
# Top-level outputs
# =============================================================================
# Populated in Phase 1.
# =============================================================================

# output "kali_public_ip" {
#   value       = module.kali.public_ip
#   description = "SSH to Kali: ssh -i <key>.pem ubuntu@<this_ip>"
# }
#
# output "wazuh_access_command" {
#   value       = "aws ssm start-session --target ${module.wazuh.instance_id} --document-name AWS-StartPortForwardingSession --parameters 'portNumber=[\"443\"],localPortNumber=[\"8443\"]'"
#   description = "Run this, then visit https://localhost:8443 in your browser."
# }
#
# output "dc_ssm_command" {
#   value       = "aws ssm start-session --target ${module.windows.dc_instance_id}"
# }
#
# output "member_ssm_command" {
#   value       = "aws ssm start-session --target ${module.windows.member_instance_id}"
# }
#
# output "domain_admin_password" {
#   value       = module.windows.domain_admin_password
#   sensitive   = true
#   description = "Retrieve with: terraform output -raw domain_admin_password"
# }
