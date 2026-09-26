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
`arn:aws:iam::211125556478:role/ad-lab-github-actions-role` via
`aws-actions/configure-aws-credentials@v4`. The role needs only `ec2:DescribeInstances`.
Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>.
