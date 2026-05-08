# =============================================================================
# AD Lateral Movement Lab — top-level composition
# =============================================================================
# Wires the five modules into one deployable stack.
#
# Module dependency graph:
#   vpc          (no upstream deps)
#   wazuh        depends on: vpc
#   windows      depends on: vpc, wazuh   (needs Wazuh IP for agent enrollment)
#   kali         depends on: vpc
#   cost_controls depends on: nothing     (operates on tagged resources)
#
# Terraform handles dependency ordering automatically based on attribute
# references (e.g., module.vpc.private_subnet_id appearing inside module.wazuh
# tells Terraform to apply vpc before wazuh).
# =============================================================================


# -----------------------------------------------------------------------------
# Network layer
# -----------------------------------------------------------------------------

module "vpc" {
  source = "./modules/vpc"

  project = var.project_tag
  # Defaults from the module are fine: 10.0.0.0/16, /24 subnets, us-east-1a
}


# -----------------------------------------------------------------------------
# SIEM (must come before windows so we can pass its IP into agent enrollment)
# -----------------------------------------------------------------------------

module "wazuh" {
  source = "./modules/wazuh"

  project           = var.project_tag
  vpc_id            = module.vpc.vpc_id
  vpc_cidr          = module.vpc.vpc_cidr
  private_subnet_id = module.vpc.private_subnet_id
  instance_type     = var.wazuh_instance_type
}


# -----------------------------------------------------------------------------
# Active Directory plane
# -----------------------------------------------------------------------------

module "windows" {
  source = "./modules/windows"

  project            = var.project_tag
  vpc_id             = module.vpc.vpc_id
  vpc_cidr           = module.vpc.vpc_cidr
  private_subnet_id  = module.vpc.private_subnet_id
  public_subnet_cidr = "10.0.1.0/24" # Kali subnet — referenced for SG rules
  instance_type      = var.windows_instance_type

  # Agents auto-enroll against this IP on first boot
  wazuh_manager_ip = module.wazuh.private_ip
}


# -----------------------------------------------------------------------------
# Attacker host
# -----------------------------------------------------------------------------

module "kali" {
  source = "./modules/kali"

  project          = var.project_tag
  vpc_id           = module.vpc.vpc_id
  public_subnet_id = module.vpc.public_subnet_id
  my_ip_cidr       = var.my_ip
  key_pair_name    = var.key_pair_name
  instance_type    = var.kali_instance_type
}


# -----------------------------------------------------------------------------
# Cost controls (independent of workload modules — operates on tag matches)
# -----------------------------------------------------------------------------

module "cost_controls" {
  source = "./modules/cost-controls"

  project            = var.project_tag
  monthly_budget_usd = var.monthly_budget_usd
  alert_email        = var.alert_email
  autostop_cron_utc  = var.autostop_cron_utc
}
