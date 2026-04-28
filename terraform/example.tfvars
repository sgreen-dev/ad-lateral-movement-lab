# =============================================================================
# Copy this file to terraform.tfvars (gitignored) and fill in your values.
# =============================================================================

# Required — your public IP, get with: curl -s ifconfig.me
my_ip = "203.0.113.42/32"

# Required — name of an existing EC2 key pair in your AWS account
key_pair_name = "lab-key"

# Required — email for cost alerts
alert_email = "you@example.com"

# Required — generate with: openssl rand -base64 24
safe_mode_password = "REPLACE_ME"

# Optional overrides
# region              = "us-east-1"
# vpc_cidr            = "10.0.0.0/16"
# windows_instance_type = "t3.medium"
# wazuh_instance_type   = "t3.large"
# monthly_budget_usd  = 25
# autostop_cron_utc   = "cron(0 3 * * ? *)"
