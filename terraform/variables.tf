# =============================================================================
# Top-level variables
# =============================================================================
# Populated in Phase 1. All variables that should NEVER be committed to git
# (e.g., my_ip, alert_email, safe_mode_password) live in terraform.tfvars,
# which is gitignored. See example.tfvars for the template.
# =============================================================================

variable "region" {
  description = "AWS region. Default us-east-1 to match the plan."
  type        = string
  default     = "us-east-1"
}

variable "project_tag" {
  description = "Tag value applied to every resource. Used by cost-controls module to scope auto-stop."
  type        = string
  default     = "ad-lateral-movement-lab"
}

variable "vpc_cidr" {
  description = "VPC CIDR. Plan default 10.0.0.0/16."
  type        = string
  default     = "10.0.0.0/16"
}

variable "my_ip" {
  description = "Operator's public IP in CIDR form (e.g., 203.0.113.42/32). Restricts SSH to Kali."
  type        = string
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for Kali SSH access."
  type        = string
}

variable "windows_ami_id" {
  description = "AMI ID for Windows Server 2022 (region-specific). Set in tfvars or resolve via data source."
  type        = string
  default     = ""
}

variable "windows_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "wazuh_instance_type" {
  type    = string
  default = "t3.large"
}

variable "domain_name" {
  type    = string
  default = "lab.local"
}

variable "safe_mode_password" {
  description = "Directory Services Restore Mode password for the DC. Generated, not hand-typed."
  type        = string
  sensitive   = true
}

variable "monthly_budget_usd" {
  description = "AWS Budgets alert threshold."
  type        = number
  default     = 25
}

variable "alert_email" {
  description = "Email for budget and cost-runaway alerts."
  type        = string
}

variable "autostop_cron_utc" {
  description = "EventBridge cron for nightly auto-stop. Default 03:00 UTC = 23:00 ET (11pm ET)."
  type        = string
  default     = "cron(0 3 * * ? *)"
}
