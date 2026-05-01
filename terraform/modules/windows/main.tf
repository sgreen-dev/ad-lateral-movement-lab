# =============================================================================
# Module: Windows
# =============================================================================
# Owns the Active Directory plane: domain controller (DC01) and member server
# (WIN01). Both Windows Server 2022, both fully instrumented.
#
# Bootstrap pattern: tiny user_data stub pulls real PS scripts from S3.
# This pattern works around the 16KB user_data limit and keeps the heavy logic
# in versioned files in the repo.
#
# State machine: PowerShell scripts write status flags to C:\bootstrap-state\
# so they're idempotent across the reboot that AD promotion forces.
# =============================================================================


# -----------------------------------------------------------------------------
# Data sources
# -----------------------------------------------------------------------------

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = [var.ami_owner]

  filter {
    name   = "name"
    values = [var.ami_name_pattern]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}


# -----------------------------------------------------------------------------
# Generated passwords — never hand-typed, never committed
# -----------------------------------------------------------------------------
# random_password keeps state in terraform.tfstate (which is gitignored).
# Retrieve at runtime with: terraform output -raw <name>

resource "random_password" "domain_admin" {
  length           = 24
  special          = true
  override_special = "!@#$%^&*()-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "random_password" "dsrm" {
  length           = 24
  special          = true
  override_special = "!@#$%^&*()-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "random_password" "alice" {
  length  = 16
  special = false # standard user — keep simple for demo screenshots
}

resource "random_password" "bob" {
  length           = 20
  special          = true
  override_special = "!@#$%^&*"
}

resource "random_password" "svc_backup" {
  length           = 28
  special          = true
  override_special = "!@#$%^&*-_"
}


# -----------------------------------------------------------------------------
# S3 bucket — holds bootstrap PS scripts pulled by user_data
# -----------------------------------------------------------------------------

resource "random_id" "bootstrap_bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "bootstrap" {
  bucket        = "${var.project}-bootstrap-${random_id.bootstrap_bucket_suffix.hex}"
  force_destroy = true # lab convenience — we want terraform destroy to clean up

  tags = {
    Name = "${var.project}-bootstrap"
  }
}

resource "aws_s3_bucket_public_access_block" "bootstrap" {
  bucket                  = aws_s3_bucket.bootstrap.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bootstrap" {
  bucket = aws_s3_bucket.bootstrap.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Upload each bootstrap script. Hashes trigger re-upload on change.
locals {
  bootstrap_scripts = {
    "10-common.ps1"       = "${path.module}/bootstrap/10-common.ps1"
    "20-promote-dc.ps1"   = "${path.module}/bootstrap/20-promote-dc.ps1"
    "30-domain-join.ps1"  = "${path.module}/bootstrap/30-domain-join.ps1"
    "40-install-art.ps1"  = "${path.module}/bootstrap/40-install-art.ps1"
  }
}

resource "aws_s3_object" "bootstrap" {
  for_each = local.bootstrap_scripts

  bucket = aws_s3_bucket.bootstrap.id
  key    = "bootstrap/${each.key}"
  source = each.value
  etag   = filemd5(each.value)
}


# -----------------------------------------------------------------------------
# IAM — instance profile for SSM + S3 read access to the bootstrap bucket
# -----------------------------------------------------------------------------

resource "aws_iam_role" "windows" {
  name = "${var.project}-windows-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-windows-role" }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.windows.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "bootstrap_s3_read" {
  name = "${var.project}-bootstrap-s3-read"
  role = aws_iam_role.windows.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
      ]
      Resource = [
        aws_s3_bucket.bootstrap.arn,
        "${aws_s3_bucket.bootstrap.arn}/*",
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "windows" {
  name = "${var.project}-windows-profile"
  role = aws_iam_role.windows.name
}


# -----------------------------------------------------------------------------
# Security groups
# -----------------------------------------------------------------------------

# DC01 — accepts AD ports from VPC, RDP/WinRM from Kali subnet only
resource "aws_security_group" "dc" {
  name        = "${var.project}-dc-sg"
  description = "Domain controller — AD ports from VPC, mgmt from Kali subnet"
  vpc_id      = var.vpc_id

  # AD DS / Kerberos / LDAP / DNS / SMB from anywhere in the VPC
  # Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts
  dynamic "ingress" {
    for_each = [
      { from = 53, to = 53, proto = "tcp", desc = "DNS TCP" },
      { from = 53, to = 53, proto = "udp", desc = "DNS UDP" },
      { from = 88, to = 88, proto = "tcp", desc = "Kerberos TCP" },
      { from = 88, to = 88, proto = "udp", desc = "Kerberos UDP" },
      { from = 135, to = 135, proto = "tcp", desc = "RPC endpoint mapper" },
      { from = 389, to = 389, proto = "tcp", desc = "LDAP TCP" },
      { from = 389, to = 389, proto = "udp", desc = "LDAP UDP" },
      { from = 445, to = 445, proto = "tcp", desc = "SMB" },
      { from = 464, to = 464, proto = "tcp", desc = "Kerberos passwd TCP" },
      { from = 464, to = 464, proto = "udp", desc = "Kerberos passwd UDP" },
      { from = 636, to = 636, proto = "tcp", desc = "LDAPS" },
      { from = 3268, to = 3269, proto = "tcp", desc = "Global catalog" },
      { from = 49152, to = 65535, proto = "tcp", desc = "RPC dynamic range" },
    ]
    content {
      from_port   = ingress.value.from
      to_port     = ingress.value.to
      protocol    = ingress.value.proto
      cidr_blocks = [var.vpc_cidr]
      description = ingress.value.desc
    }
  }

  # RDP and WinRM from Kali subnet only (for attack emulation)
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_cidr]
    description = "RDP from Kali subnet"
  }

  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_cidr]
    description = "WinRM from Kali subnet"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All egress"
  }

  tags = { Name = "${var.project}-dc-sg" }
}

# WIN01 — receives RDP/SMB/WinRM from both Kali subnet (attacker) and DC subnet
resource "aws_security_group" "member" {
  name        = "${var.project}-member-sg"
  description = "Member server — accepts lateral movement vectors from Kali and DC"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "RDP from VPC (T1021.001 vector)"
  }

  ingress {
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "SMB from VPC (T1021.002 vector)"
  }

  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "WinRM from VPC (T1021.006 vector)"
  }

  # Other AD-required ports (member needs to talk back to DC for some operations)
  ingress {
    from_port   = 135
    to_port     = 135
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "RPC endpoint mapper"
  }

  ingress {
    from_port   = 49152
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "RPC dynamic range"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All egress"
  }

  tags = { Name = "${var.project}-member-sg" }
}


# -----------------------------------------------------------------------------
# user_data — tiny stub that pulls real scripts from S3
# -----------------------------------------------------------------------------

locals {
  # Common bootstrap context passed to the scripts as PowerShell variables
  user_data_dc = templatefile("${path.module}/bootstrap/00-userdata-stub.ps1.tftpl", {
    bucket_name        = aws_s3_bucket.bootstrap.id
    role               = "dc"
    domain_name        = var.domain_name
    domain_netbios     = var.domain_netbios_name
    domain_admin_pw    = random_password.domain_admin.result
    dsrm_pw            = random_password.dsrm.result
    alice_pw           = random_password.alice.result
    bob_pw             = random_password.bob.result
    svc_backup_pw      = random_password.svc_backup.result
    wazuh_manager_ip   = var.wazuh_manager_ip
    dc_private_ip      = "" # DC doesn't need to look up itself
  })

  user_data_member = templatefile("${path.module}/bootstrap/00-userdata-stub.ps1.tftpl", {
    bucket_name        = aws_s3_bucket.bootstrap.id
    role               = "member"
    domain_name        = var.domain_name
    domain_netbios     = var.domain_netbios_name
    domain_admin_pw    = random_password.domain_admin.result
    dsrm_pw            = ""
    alice_pw           = ""
    bob_pw             = random_password.bob.result
    svc_backup_pw      = ""
    wazuh_manager_ip   = var.wazuh_manager_ip
    dc_private_ip      = aws_instance.dc.private_ip
  })
}


# -----------------------------------------------------------------------------
# EC2 instances
# -----------------------------------------------------------------------------

resource "aws_instance" "dc" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.dc.id]
  iam_instance_profile   = aws_iam_instance_profile.windows.name
  private_ip             = "10.0.2.10" # static, so member can find DC reliably

  user_data = local.user_data_dc

  # Force replacement when bootstrap scripts change
  user_data_replace_on_change = true

  root_block_device {
    volume_type = "gp3"
    volume_size = 50
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project}-dc01"
    Role = "domain-controller"
  }

  # Ensure bootstrap scripts are uploaded before instance boots
  depends_on = [aws_s3_object.bootstrap]
}

resource "aws_instance" "member" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.member.id]
  iam_instance_profile   = aws_iam_instance_profile.windows.name
  private_ip             = "10.0.2.20"

  user_data                   = local.user_data_member
  user_data_replace_on_change = true

  root_block_device {
    volume_type = "gp3"
    volume_size = 50
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project}-win01"
    Role = "member-server"
  }

  # Member must wait for DC instance to be created (for the IP); DC promotion
  # itself happens via the bootstrap script's polling loop, not Terraform.
  depends_on = [aws_instance.dc, aws_s3_object.bootstrap]
}
