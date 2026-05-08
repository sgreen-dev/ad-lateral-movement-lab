# Terraform — AD Lateral Movement Lab

Composes the four lab modules and the cost-controls module into a single deployable stack.

## Layout

```
terraform/
  main.tf              # composes modules
  variables.tf         # top-level inputs
  outputs.tf           # bubbled-up outputs from all modules
  versions.tf          # provider pins
  example.tfvars       # template for your own .tfvars
  modules/
    vpc/               # VPC, subnets, IGW, fck-nat, SSM endpoints
    windows/           # DC + member server, Sysmon/audit-policy/ART bootstrap
    wazuh/             # Wazuh all-in-one SIEM
    kali/              # Kali attacker host
    cost-controls/     # Budgets alert, EventBridge auto-stop, SNS
```

## Quick start

### 1. Prerequisites

- AWS account with admin (sandbox/personal — not a work account)
- AWS CLI configured (`aws configure`)
- Terraform ≥ 1.6 installed locally
- An existing EC2 key pair in `us-east-1` (create one in the AWS console first)

### 2. Configure

```bash
cd terraform
cp example.tfvars terraform.tfvars
# Edit terraform.tfvars — at minimum, set my_ip, key_pair_name, alert_email
```

### 3. Deploy

```bash
terraform init
terraform plan       # review what's about to be created
terraform apply
```

The apply itself takes about 2 minutes for resource creation, but the lab isn't *ready* until the Windows hosts finish bootstrapping (~15 more minutes for DC promotion + reboot + member domain join + reboot).

### 4. Confirm the SNS subscription

AWS sent you an email titled *"AWS Notification - Subscription Confirmation."* Click **"Confirm subscription"** in it. Without this step you won't receive Budgets or auto-stop alerts.

### 5. Verify the lab is up

```bash
# All four hosts should be running
terraform output

# Tunnel into Wazuh dashboard
$(terraform output -raw wazuh_dashboard_command)
# Then visit https://localhost:8443 in your browser.
# Username: admin
# Password: SSM into Wazuh and: sudo cat /etc/wazuh-install-files/wazuh-passwords.txt

# SSH into Kali to run attacks
$(terraform output -raw kali_ssh_command | sed 's|<key.pem>|/path/to/your-key.pem|')
```

## Tear down

**Run after every session.** Auto-stop is a safety net, not a substitute.

```bash
terraform destroy
```

This removes all billable resources. Cost-control resources (SNS topic, Lambda, Budget) remove with everything else.

## Cost expectations

| Scenario | Cost |
|---|---|
| Running 24/7 for 30 days | ~$165 |
| Running ~20 hours across a weekend | ~$5–8 |
| Stopped (auto-stop fired) | ~$0.10/day for EBS + EIP |
| Destroyed | $0 |

Discipline matters. Default to `terraform destroy` at end of each session.

## Variables

See [`variables.tf`](variables.tf) and [`example.tfvars`](example.tfvars).

## Outputs

See [`outputs.tf`](outputs.tf). Everything you need to reach the lab — SSH commands, SSM tunnels, sensitive credentials — is exposed at the top level.
