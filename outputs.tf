output "trailalerts_cloudtrail_analyzer_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the CloudTrail Analyzer Lambda function"
  value       = module.lambda_cloudtrail_analyzer.trailalerts_cloudtrail_analyzer_log_group_arn
}

output "trailalerts_event_processor_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the Event Processor Lambda function"
  value       = module.lambda_event_processor.trailalerts_event_processor_log_group_arn
}

# ---------------------------------------------------------------------------
# Dashboard outputs (only when enable_dashboard = true)
# ---------------------------------------------------------------------------

output "dashboard_url" {
  description = "URL to access the TrailAlerts dashboard (only when enable_dashboard is true)"
  value       = var.enable_dashboard ? module.dashboard_frontend[0].dashboard_url : null
}

output "dashboard_api_endpoint" {
  description = "API Gateway endpoint for the dashboard API (only when enable_dashboard is true)"
  value       = var.enable_dashboard ? module.dashboard_api[0].api_endpoint : null
}

output "dashboard_cognito_user_pool_id" {
  description = "Cognito User Pool ID for the dashboard (only when enable_dashboard is true)"
  value       = var.enable_dashboard ? module.cognito[0].user_pool_id : null
}