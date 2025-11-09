output "trailalerts_event_processor_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the Event Processor Lambda function"
  value       = aws_cloudwatch_log_group.trailalerts_event_processor_log_group.arn
}  