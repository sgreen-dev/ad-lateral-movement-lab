# Terraform — AD Lateral Movement Lab

Composes the four lab modules and the cost-controls module into a single deployable stack.

## Layout

```
terraform/
  main.tf              # composes modules
  variables.tf         # top-level inputs (region, my_ip, project_tag, etc.)
  outputs.tf           # public IPs, RDP/SSH commands, Wazuh URL
  versions.tf          # provider pins
  example.tfvars       # template for your own .tfvars
  modules/
    vpc/               # VPC, subnets, IGW, NAT, route tables
    windows/           # DC + member server, Sysmon/audit-policy bootstrap
    wazuh/             # Wazuh all-in-one on Ubuntu
    kali/              # Kali attacker host
    cost-controls/     # Budgets alert, EventBridge auto-stop, SNS
```

## Quick start

```bash
cd terraform
cp example.tfvars terraform.tfvars
# edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Tear down

**Run after every session.** The auto-stop is a safety net, not a substitute.

```bash
terraform destroy
```

## Variables

See [`variables.tf`](variables.tf) and [`example.tfvars`](example.tfvars).

## Outputs

See [`outputs.tf`](outputs.tf) — includes Kali public IP, Wazuh dashboard URL (via SSM port-forward instructions), and the SSM commands to reach the Windows hosts.
