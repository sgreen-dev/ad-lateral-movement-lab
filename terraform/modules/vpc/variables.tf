# =============================================================================
# Variables — VPC module
# =============================================================================

variable "project" {
  description = "Project tag prefix for all resources."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR for the VPC. Default 10.0.0.0/16."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the public subnet (Kali, NAT instance)."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR for the private subnet (Windows hosts, Wazuh)."
  type        = string
  default     = "10.0.2.0/24"
}

variable "availability_zone" {
  description = "Single AZ for the lab. Default us-east-1a."
  type        = string
  default     = "us-east-1a"
}

variable "nat_instance_type" {
  description = "Instance type for the fck-nat NAT instance. ARM64 only — fck-nat AMI requires Graviton."
  type        = string
  default     = "t4g.nano"
}
