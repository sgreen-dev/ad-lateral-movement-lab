# =============================================================================
# Variables — Kali module
# =============================================================================

variable "project" {
  description = "Project tag prefix for all resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID from the vpc module."
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet ID — Kali lives here so it has its own EIP for SSH."
  type        = string
}

variable "my_ip_cidr" {
  description = "Operator's public IP in CIDR form (e.g., 203.0.113.42/32). SSH is restricted to this only."
  type        = string
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for SSH access."
  type        = string
}

variable "instance_type" {
  description = "Instance type for Kali. t3.medium is fine for nmap/CrackMapExec/Impacket workloads."
  type        = string
  default     = "t3.medium"
}

variable "root_volume_size_gb" {
  description = "Root volume size. Kali tools + a few captures fit in 30 GB; bump if you plan to capture lots of pcaps."
  type        = number
  default     = 30
}

variable "ami_owner" {
  description = "AMI owner for Ubuntu 22.04 lookup. 099720109477 = Canonical."
  type        = string
  default     = "099720109477"
}

variable "ami_name_pattern" {
  description = "AMI name pattern for Ubuntu 22.04 LTS amd64 server."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
}
