# GitHub Actions workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| [`sigma-lint.yml`](sigma-lint.yml) | push / PR on `detections/sigma/**` | YAML + structural lint of Sigma rules; smoke-converts to SPL/KQL |
| [`terraform.yml`](terraform.yml) | push / PR on `terraform/**` | `terraform fmt -check`, `terraform validate` |
| [`cost-check.yml`](cost-check.yml) | daily 13:00 UTC | Lists running lab instances; opens an issue if any are up |

## Required repo secrets

| Secret | Used by | Notes |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | cost-check | Read-only IAM user with `ec2:DescribeInstances`. Replace with OIDC in Phase 1. |
| `AWS_SECRET_ACCESS_KEY` | cost-check | Pair with the above. |

## OIDC (planned, Phase 1)
Replace the static AWS keys with a GitHub-OIDC-trusted IAM role. Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>. The role needs only `ec2:DescribeInstances`.
