# GitHub Actions workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| [`sigma-lint.yml`](sigma-lint.yml) | push / PR on `detections/sigma/**`, `detections/splunk/**`, `detections/kql/**`, `docs/attack-navigator-layer.json`, `scripts/generate_*.py` | YAML + structural lint of Sigma rules; hard gate that runs `generate_translations.py --check` (SPL/KQL in sync) and `generate_attack_layer.py --check` (Navigator layer in sync) |
| [`wazuh-rules.yml`](wazuh-rules.yml) | push / PR on `detections/wazuh/**` | Runs `detections/wazuh/test_wazuh_rules.py`: each native Wazuh rule must match its positive fixture and reject its negative; correlation wiring checked |
| [`response-tools.yml`](response-tools.yml) | push / PR on `scripts/parsers/**`, `attack-emulation/sample-events*.json` | IOC parser unit tests + Markdown/STIX smoke run over the exemplar event set |
| [`terraform.yml`](terraform.yml) | push / PR on `terraform/**` | `terraform fmt -check`, `terraform validate` |
| [`cost-check.yml`](cost-check.yml) | daily 13:00 UTC | Lists running lab instances; opens an issue if any are up |

The Wazuh rule pack is a manual port of the Sigma rules; `wazuh-rules.yml` does not
trigger on `detections/sigma/**`, so Sigma→Wazuh drift is caught by review, not CI.

## AWS authentication (OIDC)

No repo secrets are required. `cost-check.yml` authenticates with GitHub OIDC
(`permissions: id-token: write`) and assumes the IAM role
`arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/ad-lab-github-actions-role` via
`aws-actions/configure-aws-credentials@v4`. The role needs only `ec2:DescribeInstances`.

| Repo variable | Value | Set with |
|---|---|---|
| `AWS_ACCOUNT_ID` | Lab sandbox account ID (the `lab-sso` SSO profile's account) | `gh variable set AWS_ACCOUNT_ID --body <id>` |

If the variable is unset the ARN is malformed and the job fails at *Configure AWS credentials*
— loud, which is intended. The role must live in the **same account the lab deploys into**.
If it points at another account that has the role, the job still passes — it just lists an empty
account and reports "no lab instances running" while the real lab bills. After changing
accounts, confirm with a manual run (`gh workflow run cost-check.yml`) that the
*Configure AWS credentials* step succeeds.

One-time setup in the lab account (PowerShell, signed in as `lab-sso` — see
[operator guide §0b](../../docs/operator-guide.md#0b-sign-in-to-aws-via-sso-every-session)):

```powershell
$LAB_ACCOUNT = (gh variable get AWS_ACCOUNT_ID).Trim()
aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com
$trust = @"
{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::${LAB_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
    "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:sgreen-dev/ad-lateral-movement-lab:*" } } }] }
"@
$trust | Out-File -Encoding ascii trust.json
aws iam create-role --role-name ad-lab-github-actions-role --assume-role-policy-document file://trust.json
'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}' | Out-File -Encoding ascii policy.json
aws iam put-role-policy --role-name ad-lab-github-actions-role --policy-name describe-instances --policy-document file://policy.json
Remove-Item trust.json, policy.json

# Verify: the workflow's credentials step must now succeed
gh workflow run cost-check.yml; Start-Sleep 30; gh run list --workflow cost-check.yml -L 1   # expect: completed  success
```

Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>.
