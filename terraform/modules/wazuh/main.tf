# =============================================================================
# Module: Wazuh
# =============================================================================
# Wazuh all-in-one SIEM (Manager + Indexer + Dashboard on one host) on Ubuntu
# 22.04. Sized for two endpoints reporting Sysmon + Windows Security + PS
# channels.
#
# Access: dashboard never gets a public IP. Reach it via SSM port forwarding
# from your laptop:
#   aws ssm start-session --target <wazuh_instance_id> \
#     --document-name AWS-StartPortForwardingSession \
#     --parameters portNumber=443,localPortNumber=8443
# Then https://localhost:8443
#
# State: like the Windows module, the bootstrap is idempotent. State markers
# in /var/lib/lab-bootstrap/ track install progress so re-running the user_data
# is safe.
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
# IAM — instance profile for SSM access
# -----------------------------------------------------------------------------

resource "aws_iam_role" "wazuh" {
  name = "${var.project}-wazuh-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-wazuh-role" }
}

resource "aws_iam_role_policy_attachment" "wazuh_ssm" {
  role       = aws_iam_role.wazuh.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "wazuh" {
  name = "${var.project}-wazuh-profile"
  role = aws_iam_role.wazuh.name
}


# -----------------------------------------------------------------------------
# Security group
# -----------------------------------------------------------------------------

resource "aws_security_group" "wazuh" {
  name        = "${var.project}-wazuh-sg"
  description = "Wazuh SIEM - agent comms from VPC, dashboard via SSM only"
  vpc_id      = var.vpc_id

  # Wazuh agent communication (1514/tcp) — TLS, agents -> manager
  ingress {
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh agent comms (TLS)"
  }

  # Wazuh agent enrollment (1515/tcp)
  ingress {
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh agent enrollment"
  }

  # Wazuh API (55000/tcp) — same VPC only
  ingress {
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh API"
  }

  # Dashboard (443/tcp) — SSM port forwarding from VPC only.
  # Even though SSM tunnels appear local to the host, the actual destination
  # connection still originates from inside the VPC, so this rule covers it.
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh dashboard (HTTPS) - SSM tunnel only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All egress (package installs, Wazuh updates)"
  }

  tags = { Name = "${var.project}-wazuh-sg" }
}


# -----------------------------------------------------------------------------
# user_data — runs the Wazuh all-in-one installer
# -----------------------------------------------------------------------------

locals {
  user_data = templatefile("${path.module}/bootstrap/install-wazuh.sh.tftpl", {
    wazuh_version = var.wazuh_version
  })
}


# -----------------------------------------------------------------------------
# EC2 instance
# -----------------------------------------------------------------------------

resource "aws_instance" "wazuh" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.wazuh.id]
  iam_instance_profile   = aws_iam_instance_profile.wazuh.name
  private_ip             = "10.0.2.30" # static, so Windows agents can find it

  user_data                   = local.user_data
  user_data_replace_on_change = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.data_volume_size_gb
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.project}-wazuh"
    Role = "siem"
  }
}
