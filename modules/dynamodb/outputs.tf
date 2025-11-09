output "security_events_table_name" {
  description = "The name of the DynamoDB table for security events"
  value       = aws_dynamodb_table.security_events.name
}

output "security_events_table_arn" {
  description = "The ARN of the DynamoDB table for security events"
  value       = aws_dynamodb_table.security_events.arn
}