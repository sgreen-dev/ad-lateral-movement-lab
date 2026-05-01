# =============================================================================
# Variables — Windows module
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
  description = "VPC CIDR — used for SG rules allowing intra-VPC AD traffic."
  type        = string
}

variable "private_subnet_id" {
  description = "Private subnet ID where DC and member server land."
  type        = string
}

variable "public_subnet_cidr" {
  description = "Kali subnet CIDR — referenced in SG rules so Kali can reach Windows for attack emulation."
  type        = string
}

variable "instance_type" {
  description = "Instance type for both Windows hosts. t3.medium is the floor for AD DS comfort."
  type        = string
  default     = "t3.medium"
}

variable "domain_name" {
  description = "Active Directory domain name (FQDN)."
  type        = string
  default     = "lab.local"
}

variable "domain_netbios_name" {
  description = "AD NetBIOS name. Must match the leftmost label of domain_name in uppercase for sanity."
  type        = string
  default     = "LAB"
}

variable "wazuh_manager_ip" {
  description = "Private IP of the Wazuh manager. Empty string means agent install will be skipped during initial bootstrap; rerun bootstrap or install agent manually after Wazuh is up."
  type        = string
  default     = ""
}

variable "ami_owner" {
  description = "AMI owner for Windows Server 2022 lookup. 801119661308 = Amazon's Windows AMI account."
  type        = string
  default     = "801119661308"
}

variable "ami_name_pattern" {
  description = "AMI name pattern for the latest Windows Server 2022 English Full Base."
  type        = string
  default     = "Windows_Server-2022-English-Full-Base-*"
}
