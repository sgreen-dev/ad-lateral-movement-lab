# =============================================================================
# Module: Kali
# =============================================================================
# Attacker host. Public-subnet, SSH-restricted to operator's IP. Ubuntu 22.04
# base with Kali rolling repo overlay — gets you the Kali toolset without
# the Marketplace subscribe friction of the official Kali AMI.
#
# Tools installed for lateral movement:
#   - nmap                — recon
#   - crackmapexec        — Windows enumeration + auth testing
#   - impacket-scripts    — psexec.py, wmiexec.py, secretsdump.py, etc.
#   - evil-winrm          — interactive WinRM with logon emulation
#   - freerdp2-x11        — xfreerdp for T1021.001 RDP attacks
#   - hydra               — credential testing
#   - responder           — LLMNR/NBT-NS poisoning if we go that direction later
# =============================================================================


# -----------------------------------------------------------------------------
# Data sources
# -----------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
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
# IAM — instance profile (just SSM, in case you ever want to reach Kali that way too)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "kali" {
  name = "${var.project}-kali-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-kali-role" }
}

resource "aws_iam_role_policy_attachment" "kali_ssm" {
  role       = aws_iam_role.kali.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "kali" {
  name = "${var.project}-kali-profile"
  role = aws_iam_role.kali.name
}


# -----------------------------------------------------------------------------
# Security group
# -----------------------------------------------------------------------------

resource "aws_security_group" "kali" {
  name        = "${var.project}-kali-sg"
  description = "Kali attacker — SSH from operator IP only, all egress allowed"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
    description = "SSH from operator IP only"
  }

  # All egress — this is the attack origin, it needs to reach Windows hosts on
  # arbitrary AD/SMB/WinRM/RDP ports inside the VPC, plus internet for tool updates
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All egress"
  }

  tags = { Name = "${var.project}-kali-sg" }
}


# -----------------------------------------------------------------------------
# Elastic IP — so the IP doesn't change between stops/starts
# -----------------------------------------------------------------------------

resource "aws_eip" "kali" {
  domain = "vpc"

  tags = {
    Name = "${var.project}-kali-eip"
  }
}

resource "aws_eip_association" "kali" {
  instance_id   = aws_instance.kali.id
  allocation_id = aws_eip.kali.id
}


# -----------------------------------------------------------------------------
# user_data — install Kali toolset on top of Ubuntu
# -----------------------------------------------------------------------------

locals {
  user_data = file("${path.module}/bootstrap/install-kali-tools.sh")
}


# -----------------------------------------------------------------------------
# EC2 instance
# -----------------------------------------------------------------------------

resource "aws_instance" "kali" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.public_subnet_id
  vpc_security_group_ids = [aws_security_group.kali.id]
  iam_instance_profile   = aws_iam_instance_profile.kali.name
  key_name               = var.key_pair_name

  # We assign EIP separately, but EC2 also gives this a public IP on launch
  # for the brief window before EIP association completes
  associate_public_ip_address = true

  user_data                   = local.user_data
  user_data_replace_on_change = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size_gb
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project}-kali"
    Role = "attacker"
  }
}
