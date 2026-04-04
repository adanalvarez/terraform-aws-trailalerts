output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.dashboard.id
}

output "user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.dashboard.arn
}

output "user_pool_endpoint" {
  description = "Cognito User Pool endpoint"
  value       = aws_cognito_user_pool.dashboard.endpoint
}

output "user_pool_domain" {
  description = "Cognito User Pool domain"
  value       = aws_cognito_user_pool_domain.dashboard.domain
}

output "spa_client_id" {
  description = "Cognito App Client ID for the SPA"
  value       = aws_cognito_user_pool_client.dashboard_spa.id
}
