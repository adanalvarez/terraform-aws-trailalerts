output "trailalerts_cloudtrail_analyzer_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the CloudTrail Analyzer Lambda function"
  value       = aws_cloudwatch_log_group.trailalerts_cloudtrail_analyzer_log_group.arn
}