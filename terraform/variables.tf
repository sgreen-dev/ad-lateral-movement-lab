# =============================================================================
# Top-level variables
# =============================================================================
# Variables that should NEVER be committed to git (my_ip, alert_email) live
# in terraform.tfvars (gitignored). See example.tfvars for the template.
# =============================================================================


# --- Required (user-supplied via terraform.tfvars) ---

variable "my_ip" {
  description = "Operator's public IP in CIDR form (e.g., 203.0.113.42/32). Restricts SSH to Kali."
  type        = string

  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.my_ip))
    error_message = "my_ip must be a single host CIDR like 203.0.113.42/32."
  }
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for Kali SSH access. Create one in the AWS console first."
  type        = string
}

variable "alert_email" {
  description = "Email for SNS alerts (Budgets + auto-stop). You'll receive a confirmation email on first apply."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}


# --- Optional (sensible defaults from the original plan) ---

variable "region" {
  description = "AWS region. us-east-1 is the documented default."
  type        = string
  default     = "us-east-1"
}

variable "project_tag" {
  description = "Tag value applied to every resource. Cost-controls auto-stop scopes to this exact tag value."
  type        = string
  default     = "ad-lateral-movement-lab"
}

variable "windows_instance_type" {
  description = "Instance type for both DC and member server. t3.medium is the floor for AD DS comfort."
  type        = string
  default     = "t3.medium"
}

variable "wazuh_instance_type" {
  description = "Instance type for the Wazuh all-in-one host."
  type        = string
  default     = "t3.large"
}

variable "kali_instance_type" {
  description = "Instance type for the Kali attacker host."
  type        = string
  default     = "t3.medium"
}

variable "monthly_budget_usd" {
  description = "AWS Budgets monthly threshold. Alerts at 80% actual + 100% forecasted."
  type        = number
  default     = 25
}

variable "autostop_cron_utc" {
  description = "EventBridge cron for nightly auto-stop. Default 03:00 UTC = 23:00 ET."
  type        = string
  default     = "cron(0 3 * * ? *)"
}
