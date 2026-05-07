# =============================================================================
# Variables — Cost Controls module
# =============================================================================

variable "project" {
  description = "Project tag value. The auto-stop Lambda filters EC2 by tag:Project=this."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly USD budget threshold. Alerts fire at 80% actual and 100% forecasted."
  type        = number
  default     = 25
}

variable "alert_email" {
  description = "Email subscribed to the SNS topic. Receives Budgets alerts + auto-stop reports."
  type        = string
}

variable "autostop_cron_utc" {
  description = "EventBridge cron for the nightly auto-stop. Default 03:00 UTC = 23:00 ET."
  type        = string
  default     = "cron(0 3 * * ? *)"
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention for the auto-stop Lambda. 7 days is plenty for a lab."
  type        = number
  default     = 7
}
