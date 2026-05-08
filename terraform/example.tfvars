# =============================================================================
# Copy this file to terraform.tfvars (which is gitignored) and fill in your values.
# =============================================================================

# --- REQUIRED ---

# Your public IP, get with: curl -s ifconfig.me  (then add /32)
my_ip = "203.0.113.42/32"

# Name of an existing EC2 key pair in your AWS account.
# Create one in the AWS console first: EC2 -> Key Pairs -> Create
# Save the .pem file somewhere safe and chmod 400 on macOS/Linux.
key_pair_name = "lab-key"

# Email for cost alerts. AWS sends a confirmation email on first apply —
# click the link in it to start receiving notifications.
alert_email = "you@example.com"


# --- OPTIONAL OVERRIDES (defaults are sensible) ---

# region                = "us-east-1"
# project_tag           = "ad-lateral-movement-lab"
# windows_instance_type = "t3.medium"
# wazuh_instance_type   = "t3.large"
# kali_instance_type    = "t3.medium"
# monthly_budget_usd    = 25
# autostop_cron_utc     = "cron(0 3 * * ? *)"   # 03:00 UTC nightly = 23:00 ET
