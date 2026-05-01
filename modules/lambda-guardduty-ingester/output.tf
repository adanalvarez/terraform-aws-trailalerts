output "trailalerts_guardduty_ingester_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the GuardDuty Ingester Lambda function"
  value       = aws_cloudwatch_log_group.trailalerts_guardduty_ingester_log_group.arn
}
