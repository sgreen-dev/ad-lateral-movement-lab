# =============================================================================
# Module: VPC
# =============================================================================
# Owns the network layer of the lab.
#
# Resources:
#   - VPC (10.0.0.0/16)
#   - Public subnet  (10.0.1.0/24, us-east-1a) — Kali + NAT instance
#   - Private subnet (10.0.2.0/24, us-east-1a) — Windows hosts + Wazuh
#   - Internet Gateway + public route table
#   - fck-nat NAT instance + private route table
#   - VPC endpoints (SSM trio + S3 gateway) — enables SSM Session Manager
#     access to private hosts without RDP exposure
#   - Default security groups: tightened (no implicit ingress/egress)
#
# Cost notes:
#   - NAT instance (t4g.nano): ~$0.13/day, stopped nightly by cost-controls
#   - Interface VPC endpoints: $0.01/hr each ≈ $7/mo per endpoint if running 24/7
#     We accept this for SSM access; gateway endpoints (S3) are free.
#   - For full nightly teardown, terraform destroy removes endpoints too.
# =============================================================================


# -----------------------------------------------------------------------------
# Data sources
# -----------------------------------------------------------------------------

data "aws_region" "current" {}

# fck-nat AMI — lookup latest by owner ID. The fck-nat project publishes ARM
# AMIs in every region. Reference: https://fck-nat.dev/
data "aws_ami" "fck_nat" {
  most_recent = true
  owners      = ["568608671756"] # fck-nat project's official AWS account

  filter {
    name   = "name"
    values = ["fck-nat-al2023-*-arm64-ebs"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}


# -----------------------------------------------------------------------------
# VPC + subnets
# -----------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required for SSM endpoint resolution and AD

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false # we explicitly assign EIPs where needed

  tags = {
    Name = "${var.project}-public"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = var.availability_zone

  tags = {
    Name = "${var.project}-private"
    Tier = "private"
  }
}


# -----------------------------------------------------------------------------
# Internet Gateway + public routing
# -----------------------------------------------------------------------------

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "${var.project}-rt-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


# -----------------------------------------------------------------------------
# fck-nat NAT instance
# -----------------------------------------------------------------------------

resource "aws_security_group" "nat" {
  name        = "${var.project}-nat-sg"
  description = "NAT instance — accept all from VPC, allow all egress"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "All from inside VPC (private subnet egress)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "All egress (this is the NAT)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project}-nat-sg"
  }
}

# IAM role for fck-nat (allows it to manage the route association on failover;
# also enables SSM access for ops/debug)
resource "aws_iam_role" "nat" {
  name = "${var.project}-nat-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-nat-role" }
}

resource "aws_iam_role_policy_attachment" "nat_ssm" {
  role       = aws_iam_role.nat.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# fck-nat needs to manage its ENI (for source/dest check disable + route updates
# in HA mode; we run single-AZ so this is minimal but the AMI expects it)
resource "aws_iam_role_policy" "nat_eni" {
  name = "${var.project}-nat-eni"
  role = aws_iam_role.nat.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:AttachNetworkInterface",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstances",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "nat" {
  name = "${var.project}-nat-profile"
  role = aws_iam_role.nat.name
}

resource "aws_instance" "nat" {
  ami                         = data.aws_ami.fck_nat.id
  instance_type               = var.nat_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.nat.id]
  iam_instance_profile        = aws_iam_instance_profile.nat.name
  associate_public_ip_address = true
  source_dest_check           = false # mandatory for any NAT instance

  # fck-nat AMI is self-configuring on boot; no user_data required for basic operation

  tags = {
    Name = "${var.project}-nat"
    Role = "nat"
  }
}


# -----------------------------------------------------------------------------
# Private routing — point at the NAT instance's ENI
# -----------------------------------------------------------------------------

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_instance.nat.primary_network_interface_id
  }

  tags = {
    Name = "${var.project}-rt-private"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}


# -----------------------------------------------------------------------------
# VPC endpoints — enables SSM Session Manager to private Windows hosts
# without RDP exposure or NAT traversal for control-plane traffic
# -----------------------------------------------------------------------------

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project}-vpce-sg"
  description = "VPC interface endpoints — accept HTTPS from VPC"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "All egress (replies)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-vpce-sg" }
}

# Interface endpoints (the SSM trio)
locals {
  interface_endpoints = toset([
    "ssm",
    "ssmmessages",
    "ec2messages",
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project}-vpce-${each.key}"
  }
}

# Gateway endpoint for S3 — free, used by SSM agent for patch baselines and any
# bootstrap that pulls from S3 buckets
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "${var.project}-vpce-s3"
  }
}


# -----------------------------------------------------------------------------
# Default security group — strip all rules
# -----------------------------------------------------------------------------
# AWS creates a default SG per VPC with allow-all-from-self ingress and
# allow-all egress. Best practice: empty it. Resources should use explicit SGs.

resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project}-default-sg-locked"
  }
  # No ingress, no egress blocks — both default to empty
}
