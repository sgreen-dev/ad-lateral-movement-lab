# =============================================================================
# AD Lateral Movement Lab — top-level composition
# =============================================================================
# This file wires together the modules. Each module owns one concern.
# Body intentionally left as scaffolding; populated in Phase 1 build.
# =============================================================================

# ---- VPC, subnets, routing ----
# module "vpc" {
#   source     = "./modules/vpc"
#   project    = var.project_tag
#   vpc_cidr   = var.vpc_cidr
# }

# ---- Windows hosts (DC + member server) ----
# module "windows" {
#   source              = "./modules/windows"
#   project             = var.project_tag
#   private_subnet_id   = module.vpc.private_subnet_id
#   vpc_id              = module.vpc.vpc_id
#   ami_id              = var.windows_ami_id
#   instance_type       = var.windows_instance_type
#   domain_name         = var.domain_name
#   safe_mode_password  = var.safe_mode_password  # marked sensitive in variables.tf
# }

# ---- Wazuh SIEM ----
# module "wazuh" {
#   source              = "./modules/wazuh"
#   project             = var.project_tag
#   private_subnet_id   = module.vpc.private_subnet_id
#   vpc_id              = module.vpc.vpc_id
#   instance_type       = var.wazuh_instance_type
# }

# ---- Kali attacker ----
# module "kali" {
#   source             = "./modules/kali"
#   project            = var.project_tag
#   public_subnet_id   = module.vpc.public_subnet_id
#   vpc_id             = module.vpc.vpc_id
#   my_ip_cidr         = var.my_ip
#   key_pair_name      = var.key_pair_name
# }

# ---- Cost controls ----
# module "cost_controls" {
#   source                  = "./modules/cost-controls"
#   project                 = var.project_tag
#   monthly_budget_usd      = var.monthly_budget_usd
#   alert_email             = var.alert_email
#   instance_ids_to_autostop = [
#     module.windows.dc_instance_id,
#     module.windows.member_instance_id,
#     module.wazuh.instance_id,
#     module.kali.instance_id,
#   ]
#   autostop_cron_utc       = var.autostop_cron_utc
# }
