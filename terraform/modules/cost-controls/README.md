# Module: Cost Controls

The financial seat-belt. Three independent layers; if all three fail you owe AWS money, which is the right amount of paranoia for a personal lab.

## Layer 1 — AWS Budgets alert
- Monthly budget at `var.monthly_budget_usd` (default $25)
- SNS topic + email subscription to `var.alert_email`
- Triggers at 80% actual and 100% forecasted

## Layer 2 — EventBridge nightly auto-stop
- EventBridge rule on `var.autostop_cron_utc` (default 03:00 UTC, ~11pm ET)
- Targets a Lambda function (Python 3.12) that:
  1. `ec2:DescribeInstances` filtered by `tag:Project = var.project_tag`
  2. Calls `ec2:StopInstances` on every running instance found
  3. Publishes a summary to the same SNS topic as Budgets
- IAM role scoped tightly: only `ec2:Describe*`, `ec2:StopInstances`, and `sns:Publish`

## Layer 3 — GitHub Actions cost-runaway check
Lives in `.github/workflows/cost-check.yml`, not in Terraform itself, but documented here. Runs daily, lists running instances by project tag, opens a GitHub issue on the repo if anything is up.

## Outputs
- `sns_topic_arn`
- `lambda_function_name`
- `budget_name`

## Why three layers
Budgets is reactive (alerts after spend). EventBridge stops things proactively but only at one time of day. The GHA check is your independent observer in case the Lambda role gets revoked or the EventBridge rule is disabled by mistake.
