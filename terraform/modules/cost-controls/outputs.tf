# =============================================================================
# Outputs — Cost Controls module
# =============================================================================

output "sns_topic_arn" {
  description = "SNS topic for cost alerts. Other modules can subscribe to this for ad-hoc notifications."
  value       = aws_sns_topic.alerts.arn
}

output "budget_name" {
  description = "AWS Budgets resource name."
  value       = aws_budgets_budget.monthly.name
}

output "lambda_function_name" {
  description = "Auto-stop Lambda function name. Useful for manual invocation: aws lambda invoke --function-name <this> /dev/stdout"
  value       = aws_lambda_function.auto_stop.function_name
}

output "lambda_log_group" {
  description = "CloudWatch log group for the auto-stop Lambda. Tail with: aws logs tail <this> --follow"
  value       = aws_cloudwatch_log_group.auto_stop.name
}

output "test_lambda_command" {
  description = "Manually invoke the auto-stop Lambda to test. Output goes to stdout."
  value       = "aws lambda invoke --function-name ${aws_lambda_function.auto_stop.function_name} /tmp/lambda-out.json && cat /tmp/lambda-out.json"
}
