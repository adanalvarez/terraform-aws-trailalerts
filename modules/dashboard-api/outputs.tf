output "api_endpoint" {
  description = "The API Gateway endpoint URL"
  value       = aws_apigatewayv2_api.dashboard.api_endpoint
}

output "api_id" {
  description = "The API Gateway ID"
  value       = aws_apigatewayv2_api.dashboard.id
}

output "dashboard_api_log_group_arn" {
  description = "CloudWatch Log Group ARN for the dashboard API Lambda"
  value       = aws_cloudwatch_log_group.dashboard_api_log_group.arn
}
