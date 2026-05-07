# =============================================================================
# Module: Cost Controls
# =============================================================================
# Three independent layers of cost defense:
#   Layer 1 — AWS Budgets alert at 80%/100% of monthly_budget_usd
#   Layer 2 — EventBridge nightly auto-stop (this module's Lambda)
#   Layer 3 — GitHub Actions cost-runaway check (in .github/workflows/)
#
# All notifications flow through one SNS topic so there's a single inbox
# channel for "lab is doing something I should know about."
# =============================================================================


# -----------------------------------------------------------------------------
# Data sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


# -----------------------------------------------------------------------------
# SNS — single notification topic
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project}-cost-alerts"

  tags = { Name = "${var.project}-cost-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email

  # Note: AWS sends a confirmation email to var.alert_email on first apply.
  # The subscription is "PendingConfirmation" until the recipient clicks the
  # link in that email. Budgets and the auto-stop Lambda will publish to the
  # topic regardless; only delivery is gated on confirmation.
}

# Allow Budgets service to publish to this topic
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBudgetsPublish"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      },
    ]
  })
}


# -----------------------------------------------------------------------------
# Layer 1 — AWS Budgets
# -----------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name              = "${var.project}-monthly"
  budget_type       = "COST"
  limit_amount      = tostring(var.monthly_budget_usd)
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2026-01-01_00:00"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$${var.project}"]
  }

  # Alert at 80% of actual spend
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
  }

  # Alert at 100% forecasted (gives you a heads-up before you hit the cap)
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
  }
}


# -----------------------------------------------------------------------------
# Layer 2 — Auto-stop Lambda
# -----------------------------------------------------------------------------

# Package the function code into a zip
data "archive_file" "auto_stop" {
  type        = "zip"
  source_file = "${path.module}/lambda/auto_stop.py"
  output_path = "${path.module}/lambda/auto_stop.zip"
}

# IAM role for the Lambda
resource "aws_iam_role" "auto_stop" {
  name = "${var.project}-autostop-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project}-autostop-role" }
}

# Tightly scoped permissions: describe + stop EC2, publish to our SNS topic, write logs
resource "aws_iam_role_policy" "auto_stop" {
  name = "${var.project}-autostop-policy"
  role = aws_iam_role.auto_stop.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:StopInstances",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
    ]
  })
}

# Pre-create the log group so we control retention (Lambda would create it
# with retention = Never Expire by default)
resource "aws_cloudwatch_log_group" "auto_stop" {
  name              = "/aws/lambda/${var.project}-autostop"
  retention_in_days = var.lambda_log_retention_days

  tags = { Name = "${var.project}-autostop-logs" }
}

resource "aws_lambda_function" "auto_stop" {
  function_name = "${var.project}-autostop"
  role          = aws_iam_role.auto_stop.arn
  handler       = "auto_stop.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60

  filename         = data.archive_file.auto_stop.output_path
  source_code_hash = data.archive_file.auto_stop.output_base64sha256

  environment {
    variables = {
      PROJECT_TAG   = var.project
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.auto_stop,
    aws_iam_role_policy.auto_stop,
  ]

  tags = { Name = "${var.project}-autostop" }
}

# EventBridge schedule — fires the Lambda nightly
resource "aws_cloudwatch_event_rule" "nightly_autostop" {
  name                = "${var.project}-nightly-autostop"
  description         = "Stops all EC2 instances tagged Project=${var.project} nightly"
  schedule_expression = var.autostop_cron_utc

  tags = { Name = "${var.project}-nightly-autostop" }
}

resource "aws_cloudwatch_event_target" "nightly_autostop" {
  rule      = aws_cloudwatch_event_rule.nightly_autostop.name
  target_id = "autostop-lambda"
  arn       = aws_lambda_function.auto_stop.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_stop.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.nightly_autostop.arn
}
