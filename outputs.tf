output "trailalerts_cloudtrail_analyzer_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the CloudTrail Analyzer Lambda function"
  value       = module.lambda_cloudtrail_analyzer.trailalerts_cloudtrail_analyzer_log_group_arn
}

output "trailalerts_event_processor_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the Event Processor Lambda function"
  value       = module.lambda_event_processor.trailalerts_event_processor_log_group_arn
}