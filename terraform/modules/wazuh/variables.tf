# =============================================================================
# Variables — Wazuh module
# =============================================================================

variable "project" {
  description = "Project tag prefix for all resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID from the vpc module."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR — used to scope agent ingress to the VPC only."
  type        = string
}

variable "private_subnet_id" {
  description = "Private subnet ID where the SIEM lands."
  type        = string
}

variable "instance_type" {
  description = "Instance type for the Wazuh all-in-one host. t3.large is the documented floor for indexer + dashboard + manager."
  type        = string
  default     = "t3.large"
}

variable "data_volume_size_gb" {
  description = "Size of the indexer data volume in GB."
  type        = number
  default     = 50
}

variable "wazuh_version" {
  description = "Wazuh version to install. Pinned for reproducibility."
  type        = string
  default     = "4.14"
}

variable "ami_owner" {
  description = "AMI owner for Ubuntu 22.04 lookup. 099720109477 = Canonical."
  type        = string
  default     = "099720109477"
}

variable "ami_name_pattern" {
  description = "AMI name pattern for Ubuntu 22.04 LTS amd64 server."
  type        = string
  default     = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}
