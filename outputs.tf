output "trailalerts_cloudtrail_analyzer_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the CloudTrail Analyzer Lambda function"
  value       = module.lambda_cloudtrail_analyzer.trailalerts_cloudtrail_analyzer_log_group_arn
}

output "trailalerts_event_processor_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the Event Processor Lambda function"
  value       = module.lambda_event_processor.trailalerts_event_processor_log_group_arn
}

output "trailalerts_guardduty_ingester_log_group_arn" {
  description = "The ARN of the CloudWatch Log Group for the GuardDuty Ingester Lambda function (only when enable_guardduty_ingestion is true)"
  value       = var.enable_guardduty_ingestion ? module.lambda_guardduty_ingester[0].trailalerts_guardduty_ingester_log_group_arn : null
}

output "guardduty_export_destination_ids" {
  description = "GuardDuty publishing destination IDs keyed by region (only when enable_guardduty_export_destinations is true)"
  value       = var.enable_guardduty_export_destinations ? module.guardduty_export_destinations[0].guardduty_export_destination_ids : {}
}

output "guardduty_export_bucket_policy_json" {
  description = "Policy document that can be merged into the central GuardDuty export bucket policy (only when enable_guardduty_export_destinations is true)"
  value       = var.enable_guardduty_export_destinations ? module.guardduty_export_destinations[0].guardduty_export_bucket_policy_json : null
}

output "guardduty_export_kms_key_policy_json" {
  description = "Policy document that can be merged into the GuardDuty export KMS key policy (only when enable_guardduty_export_destinations is true)"
  value       = var.enable_guardduty_export_destinations ? module.guardduty_export_destinations[0].guardduty_export_kms_key_policy_json : null
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